package dev.raspberry;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.preference.PreferenceManager;
import android.util.Log;
import android.net.http.X509TrustManagerExtensions;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import dev.raspberry.core.Attempt;
import dev.raspberry.core.AuthUrl;
import dev.raspberry.core.Callback;
import dev.raspberry.core.Descriptor;
import dev.raspberry.core.HexPin;
import dev.raspberry.core.Json;
import dev.raspberry.core.PinPolicy;
import dev.raspberry.core.Pkce;
import dev.raspberry.core.UuidShape;
import dev.raspberry.core.WebRewrite;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * classes5 entry points. The dex patch calls these directly. No manifest entries.
 * JNI: Java_dev_raspberry_Raspberry_installNative (Ljava/lang/String;[I)Z
 * ports are mapped values in order 80, 443, 10000, 10123.
 */
public final class Raspberry {
    static final String PREF_UUID = "uuid";
    static final String PREF_MARKER = "raspberry.discord";
    private static final int MAX_BODY = 16 * 1024;
    private static final int MAX_HTTP = 4096;
    private static final int MAX_ACCEPTS = 8;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private static volatile Context app;
    private static volatile Descriptor endpoint;
    private static volatile byte[] pin;
    private static volatile int config; // 0 unread, 1 ok, 2 bad
    private static volatile boolean nativeInstalled;
    private static SSLSocketFactory pinned;
    private static String pinnedHost;
    private static boolean pinLogged;

    private static final Attempt attempt = new Attempt();
    private static ServerSocket socket;
    private static Thread waiter;
    private static Pkce pkce;
    private static int liveGen;

    private static Dialog dialog;
    private static Activity dialogActivity;
    private static TextView statusView;
    private static Button discordBtn;
    private static Button retryBtn;
    private static boolean failed;

    private Raspberry() {}

    /**
     * Stock guest id, or empty. A leftover uuid without our marker is not a login.
     * Does not mint, and does not read ANDROID_ID.
     */
    public static String deviceUuid(Context context) {
        if (context == null) {
            return "";
        }
        Context application = context.getApplicationContext();
        if (application == null) {
            application = context;
        }
        capture(application);
        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(application);
            if (!prefs.getBoolean(PREF_MARKER, false)) {
                return "";
            }
            String uuid = prefs.getString(PREF_UUID, "");
            if (!UuidShape.ok(uuid)) {
                return "";
            }
            return uuid;
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** Main thread, every 500 ms. Never blocks and never starts OAuth by itself. */
    public static boolean beforeNative(Activity activity) {
        if (activity == null) {
            return false;
        }
        capture(activity.getApplicationContext());
        if (activity.isFinishing() || activity.isDestroyed()) {
            if (dialogActivity == activity) {
                dismiss();
            }
            abandon();
            return false;
        }
        if (deviceUuid(activity).length() > 0) {
            dismiss();
            return true;
        }
        ensureConfig(activity.getApplicationContext());
        boolean showing = dialog != null && dialogActivity == activity && dialog.isShowing();
        if (!showing && !activity.hasWindowFocus()) {
            return false;
        }
        show(activity);
        return false;
    }

    /** After libgame is loaded, before cusCocosInit. No auth network. */
    public static void afterGameLoad(Activity activity) {
        if (activity == null) {
            throw new IllegalStateException("raspberry");
        }
        Context application = activity.getApplicationContext();
        capture(application);
        if (!ensureConfig(application)) {
            throw new IllegalStateException("raspberry");
        }
        if (nativeInstalled) {
            return;
        }
        System.loadLibrary("raspberry");
        if (!installNative(endpoint.host(), endpoint.nativePorts())) {
            throw new IllegalStateException("raspberry");
        }
        nativeInstalled = true;
    }

    public static String rewrite(String url) {
        Descriptor d = endpoint;
        if (d == null && app != null) {
            ensureConfig(app);
            d = endpoint;
        }
        return WebRewrite.rewrite(url, d);
    }

    private static native boolean installNative(String host, int[] ports);

    private static void capture(Context context) {
        if (context != null) {
            app = context;
        }
    }

    private static boolean ensureConfig(Context context) {
        if (config == 1) {
            return true;
        }
        if (config == 2 || context == null) {
            return false;
        }
        synchronized (Raspberry.class) {
            if (config == 1) {
                return true;
            }
            if (config == 2) {
                return false;
            }
            try {
                byte[] raw = readEndpoint(context);
                endpoint = Descriptor.parse(new String(raw, StandardCharsets.UTF_8));
                pin = readPin(context);
                if (pin != null && !pinLogged) {
                    pinLogged = true;
                    Log.w("raspberry", "developer certificate pin active; not a normal build");
                }
                config = 1;
                return true;
            } catch (Exception e) {
                endpoint = null;
                pin = null;
                config = 2;
                return false;
            }
        }
    }

    private static byte[] readEndpoint(Context context) throws Exception {
        File override = new File(new File(context.getFilesDir(), "raspberry"), "endpoint.json");
        InputStream in = null;
        try {
            if (override.isFile()) {
                in = new FileInputStream(override);
            } else {
                in = context.getAssets().open("raspberry/endpoint.json");
            }
            return readCap(in, Descriptor.MAX_CHARS, false);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    private static byte[] readPin(Context context) throws Exception {
        InputStream in = null;
        try {
            in = context.getAssets().open("raspberry/devPinSha256");
        } catch (FileNotFoundException e) {
            return null;
        }
        try {
            byte[] raw = readCap(in, Descriptor.MAX_CHARS, true);
            if (raw == null) {
                return null;
            }
            return HexPin.parse(new String(raw, StandardCharsets.UTF_8));
        } finally {
            in.close();
        }
    }

    private static byte[] readCap(InputStream in, int cap, boolean emptyOk) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) >= 0) {
            total += n;
            if (total > cap) {
                throw new IllegalStateException("raspberry");
            }
            out.write(buf, 0, n);
        }
        if (total == 0) {
            if (emptyOk) {
                return null;
            }
            throw new IllegalStateException("raspberry");
        }
        return out.toByteArray();
    }

    private static void show(final Activity activity) {
        if (dialog != null && dialogActivity == activity && dialog.isShowing()) {
            bindButtons();
            return;
        }
        dismiss();
        LinearLayout root = new LinearLayout(activity);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * activity.getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        TextView title = new TextView(activity);
        title.setText("Discord sign-in");
        root.addView(title);
        if (pin != null) {
            TextView warn = new TextView(activity);
            warn.setText("LAB PIN: this build checks a developer certificate pin. Not a normal build.");
            root.addView(warn);
        }
        statusView = new TextView(activity);
        statusView.setText(statusText());
        root.addView(statusView);
        discordBtn = button(activity, "Discord", new View.OnClickListener() {
            public void onClick(View v) {
                start(activity);
            }
        });
        retryBtn = button(activity, "Retry", new View.OnClickListener() {
            public void onClick(View v) {
                retry(activity);
            }
        });
        Button exit = button(activity, "Exit", new View.OnClickListener() {
            public void onClick(View v) {
                abandon();
                dismiss();
                activity.finish();
            }
        });
        root.addView(discordBtn);
        root.addView(retryBtn);
        root.addView(exit);
        Dialog d = new Dialog(activity);
        d.setCancelable(false);
        d.setCanceledOnTouchOutside(false);
        d.setContentView(root);
        dialog = d;
        dialogActivity = activity;
        bindButtons();
        try {
            d.show();
        } catch (RuntimeException e) {
            dismiss();
        }
    }

    private static Button button(Activity activity, String label, View.OnClickListener click) {
        Button b = new Button(activity);
        b.setText(label);
        b.setOnClickListener(click);
        return b;
    }

    private static void bindButtons() {
        boolean live = liveGen != 0 && attempt.live(liveGen);
        if (discordBtn != null) {
            discordBtn.setEnabled(!live && config != 2);
        }
        if (retryBtn != null) {
            retryBtn.setEnabled(live || failed);
        }
        if (statusView != null) {
            statusView.setText(statusText());
        }
    }

    private static String statusText() {
        if (config == 2) {
            return "Sign-in is unavailable.";
        }
        if (liveGen != 0 && attempt.live(liveGen)) {
            return "Waiting for the browser.";
        }
        if (failed) {
            return "Sign-in failed. Tap Retry.";
        }
        return "Sign in with Discord to continue.";
    }

    private static void start(Activity activity) {
        if (liveGen != 0 && attempt.live(liveGen)) {
            return;
        }
        if (!ensureConfig(activity.getApplicationContext()) || endpoint == null) {
            setStatus("Sign-in is unavailable.");
            return;
        }
        ServerSocket ss = null;
        int gen = 0;
        boolean armed = false;
        try {
            ss = new ServerSocket();
            ss.setReuseAddress(false);
            ss.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0));
            int port = ss.getLocalPort();
            String ret = AuthUrl.loopback(port);
            Pkce next = Pkce.generate();
            String state = Pkce.newState();
            String url = ret == null ? null : AuthUrl.start(endpoint, next.challenge, ret, state);
            if (url == null) {
                failed = true;
                setStatus("Sign-in failed. Tap Retry.");
                return;
            }
            long now = System.nanoTime();
            gen = attempt.begin(state, now);
            if (gen == 0) {
                failed = true;
                setStatus("Sign-in failed. Tap Retry.");
                return;
            }
            ss.setSoTimeout(1000);
            pkce = next;
            socket = ss;
            Thread thread = new Thread(acceptLoop(gen, ss, now + Attempt.LIMIT_NS), "raspberry-cb");
            thread.setDaemon(true);
            waiter = thread;
            thread.start();
            liveGen = gen;
            openBrowser(activity, Uri.parse(url));
            armed = true;
            failed = false;
            setStatus("Waiting for the browser.");
            bindButtons();
        } catch (Exception e) {
            failed = true;
            setStatus("Sign-in failed. Tap Retry.");
        } finally {
            if (!armed) {
                close(ss);
                if (socket == ss) {
                    socket = null;
                }
                if (gen != 0) {
                    attempt.cancel(gen);
                }
                clearSecrets(gen);
                if (liveGen == gen) {
                    liveGen = 0;
                }
            }
        }
    }

    private static void retry(Activity activity) {
        if (liveGen != 0 && attempt.live(liveGen)) {
            abandon();
            failed = true;
            setStatus("Cancelled. Tap Discord to try again.");
            bindButtons();
            return;
        }
        if (failed) {
            start(activity);
        }
    }

    private static void openBrowser(Activity activity, Uri uri) {
        try {
            Class<?> builderCls = Class.forName("androidx.browser.customtabs.CustomTabsIntent$Builder");
            Object builder = builderCls.getConstructor().newInstance();
            Object tabs = builderCls.getMethod("build").invoke(builder);
            tabs.getClass().getMethod("launchUrl", Context.class, Uri.class).invoke(tabs, activity, uri);
            return;
        } catch (Throwable ignored) {
            // Custom Tabs is in the APK; ACTION_VIEW is the fallback. Do not log the URL.
        }
        activity.startActivity(new Intent(Intent.ACTION_VIEW, uri));
    }

    private static Runnable acceptLoop(final int gen, final ServerSocket ss, final long deadline) {
        return new Runnable() {
            public void run() {
                int accepts = 0;
                try {
                    while (System.nanoTime() < deadline && attempt.live(gen)) {
                        Socket client = null;
                        try {
                            client = ss.accept();
                        } catch (SocketTimeoutException e) {
                            continue;
                        }
                        accepts++;
                        if (accepts > MAX_ACCEPTS || client.getInetAddress() == null || !client.getInetAddress().isLoopbackAddress()) {
                            close(client);
                            if (accepts > MAX_ACCEPTS) {
                                break;
                            }
                            continue;
                        }
                        Callback cb = readCallback(client);
                        int decision = attempt.onCallback(gen, cb, System.nanoTime());
                        if (decision == Attempt.EXCHANGE) {
                            write(client, 200, "You can close this tab.");
                            close(client);
                            finishExchange(gen, cb.ticket);
                            return;
                        }
                        if (decision == Attempt.FAIL) {
                            write(client, 400, "Sign-in failed.");
                            close(client);
                            markFailed(gen);
                            return;
                        }
                        write(client, cb == null ? 404 : 400, "Ignored.");
                        close(client);
                    }
                    if (attempt.live(gen)) {
                        attempt.fail(gen);
                        markFailed(gen);
                    }
                } catch (Exception e) {
                    if (attempt.live(gen)) {
                        attempt.fail(gen);
                        markFailed(gen);
                    }
                } finally {
                    close(ss);
                    clearSecrets(gen);
                }
            }
        };
    }

    private static void finishExchange(final int gen, String ticket) {
        Pkce proof = pkce;
        String code = null;
        try {
            if (proof == null || !attempt.live(gen)) {
                attempt.fail(gen);
                markFailed(gen);
                return;
            }
            try {
                code = postExchange(ticket, proof.verifier);
            } catch (Exception e) {
                code = null;
            }
            if (!attempt.live(gen) || code == null || !commit(code)) {
                attempt.fail(gen);
                markFailed(gen);
                return;
            }
            attempt.done(gen);
            MAIN.post(new Runnable() {
                public void run() {
                    liveGen = 0;
                    if (app != null && deviceUuid(app).length() > 0) {
                        dismiss();
                    }
                }
            });
        } finally {
            code = null;
            clearSecrets(gen);
        }
    }

    private static boolean commit(String code) {
        Context context = app;
        if (context == null || !UuidShape.ok(code)) {
            return false;
        }
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences.Editor ed = prefs.edit();
        ed.putBoolean(PREF_MARKER, true);
        ed.putString(PREF_UUID, code);
        boolean wrote = false;
        try {
            wrote = ed.commit();
        } catch (RuntimeException e) {
            wrote = false;
        }
        if (!wrote || !prefs.getBoolean(PREF_MARKER, false) || !code.equals(prefs.getString(PREF_UUID, ""))) {
            clearLogin(prefs);
            return false;
        }
        return true;
    }

    private static void clearLogin(SharedPreferences prefs) {
        try {
            SharedPreferences.Editor ed = prefs.edit();
            ed.remove(PREF_UUID);
            ed.putBoolean(PREF_MARKER, false);
            ed.commit();
        } catch (RuntimeException ignored) {
            // a failed commit must not leave a login in memory
        }
    }

    private static String postExchange(String ticket, String verifier) throws Exception {
        if (!AuthUrl.ticket(ticket) || !AuthUrl.verifier(verifier) || endpoint == null) {
            return null;
        }
        byte[] body = ("{\"ticket\":\"" + ticket + "\",\"verifier\":\"" + verifier + "\"}").getBytes(StandardCharsets.US_ASCII);
        if (body.length > 4096) {
            return null;
        }
        HttpURLConnection raw = (HttpURLConnection) new URL(AuthUrl.exchange(endpoint)).openConnection();
        if (!(raw instanceof HttpsURLConnection)) {
            raw.disconnect();
            return null;
        }
        HttpsURLConnection conn = (HttpsURLConnection) raw;
        try {
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setUseCaches(false);
            conn.setDoOutput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");
            conn.setFixedLengthStreamingMode(body.length);
            if (pin != null) {
                conn.setSSLSocketFactory(pinFactory(pin, endpoint.host()));
            }
            OutputStream out = conn.getOutputStream();
            out.write(body);
            out.close();
            int status = conn.getResponseCode();
            if (status != 200) {
                discard(conn.getErrorStream());
                return null;
            }
            byte[] got = readCap(conn.getInputStream(), MAX_BODY, false);
            return Json.uniqueCode(new String(got, StandardCharsets.UTF_8));
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Pin is extra. Platform TrustManager first, then Android
     * X509TrustManagerExtensions for the endpoint host, then the leaf DER pin.
     * Null KeyStore is the platform store. If that hostname API cannot be
     * constructed, this throws and no factory is installed.
     */
    private static SSLSocketFactory pinFactory(final byte[] expect, final String host) throws Exception {
        if (expect == null || expect.length != 32 || host == null || host.length() == 0) {
            throw new CertificateException("pin");
        }
        synchronized (Raspberry.class) {
            if (pinned != null && host.equals(pinnedHost)) {
                return pinned;
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            X509TrustManager platformTm = null;
            TrustManager[] managers = tmf.getTrustManagers();
            if (managers != null) {
                for (int i = 0; i < managers.length; i++) {
                    if (managers[i] instanceof X509TrustManager) {
                        platformTm = (X509TrustManager) managers[i];
                        break;
                    }
                }
            }
            if (platformTm == null) {
                throw new CertificateException("pin");
            }
            final X509TrustManager base = platformTm;
            final X509TrustManagerExtensions ext;
            try {
                ext = new X509TrustManagerExtensions(base);
            } catch (IllegalArgumentException e) {
                throw new CertificateException("pin");
            }
            final String endpointHost = host;
            TrustManager wrapped = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    throw new CertificateException("pin");
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    base.checkServerTrusted(chain, authType);
                    List<X509Certificate> checked = ext.checkServerTrusted(chain, authType, endpointHost);
                    if (checked == null || checked.isEmpty() || checked.get(0) == null) {
                        throw new CertificateException("pin");
                    }
                    try {
                        byte[] got = MessageDigest.getInstance("SHA-256").digest(checked.get(0).getEncoded());
                        if (!PinPolicy.accept(true, true, got, expect)) {
                            throw new CertificateException("pin");
                        }
                    } catch (CertificateException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new CertificateException("pin");
                    }
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return base.getAcceptedIssuers();
                }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[] {wrapped}, null);
            pinned = sc.getSocketFactory();
            pinnedHost = host;
            return pinned;
        }
    }

    private static Callback readCallback(Socket client) {
        try {
            client.setSoTimeout(5000);
            InputStream in = client.getInputStream();
            byte[] buf = new byte[MAX_HTTP];
            int got = 0;
            int lineEnd = -1;
            while (got < buf.length && lineEnd < 0) {
                int n = in.read(buf, got, buf.length - got);
                if (n < 0) {
                    break;
                }
                got += n;
                lineEnd = findCrlf(buf, got);
            }
            if (lineEnd < 0) {
                return null;
            }
            String line = new String(buf, 0, lineEnd, StandardCharsets.US_ASCII);
            return Callback.parseLine(line);
        } catch (Exception e) {
            return null;
        }
    }

    private static int findCrlf(byte[] buf, int len) {
        for (int i = 0; i + 1 < len; i++) {
            if (buf[i] == '\r' && buf[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static void write(Socket client, int status, String text) {
        try {
            byte[] body = text.getBytes(StandardCharsets.US_ASCII);
            String head = "HTTP/1.1 " + status + " \r\nContent-Length: " + body.length
                    + "\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
            OutputStream out = client.getOutputStream();
            out.write(head.getBytes(StandardCharsets.US_ASCII));
            out.write(body);
            out.flush();
        } catch (Exception ignored) {
            // the browser can fail; the attempt decision already happened
        }
    }

    private static void discard(InputStream in) {
        if (in == null) {
            return;
        }
        try {
            byte[] buf = new byte[1024];
            int n = 0;
            int got = 0;
            while (got < 1024 && (n = in.read(buf)) >= 0) {
                got += n;
            }
        } catch (Exception ignored) {
            // ignore
        }
    }

    private static void markFailed(final int gen) {
        MAIN.post(new Runnable() {
            public void run() {
                if (liveGen != gen) {
                    return;
                }
                failed = true;
                clearSecrets(gen);
                liveGen = 0;
                setStatus("Sign-in failed. Tap Retry.");
                bindButtons();
            }
        });
    }

    private static void abandon() {
        int gen = liveGen;
        if (gen != 0) {
            attempt.cancel(gen);
        }
        close(socket);
        socket = null;
        clearSecrets(gen);
        liveGen = 0;
    }

    private static void clearSecrets(int gen) {
        if (gen == 0 || gen == liveGen || !attempt.live(gen)) {
            pkce = null;
        }
    }

    private static void setStatus(final String text) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (statusView != null) {
                statusView.setText(text);
            }
            return;
        }
        MAIN.post(new Runnable() {
            public void run() {
                if (statusView != null) {
                    statusView.setText(text);
                }
            }
        });
    }

    private static void dismiss() {
        Dialog d = dialog;
        dialog = null;
        dialogActivity = null;
        statusView = null;
        discordBtn = null;
        retryBtn = null;
        if (d != null) {
            try {
                d.dismiss();
            } catch (RuntimeException ignored) {
                // the activity is already gone
            }
        }
    }

    private static void close(Socket s) {
        if (s == null) {
            return;
        }
        try {
            s.close();
        } catch (Exception ignored) {
            // ignore
        }
    }

    private static void close(ServerSocket s) {
        if (s == null) {
            return;
        }
        try {
            s.close();
        } catch (Exception ignored) {
            // ignore
        }
    }
}
