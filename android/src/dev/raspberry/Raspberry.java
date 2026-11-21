package dev.raspberry;

import android.app.Activity;
import android.app.Application;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Bundle;
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
import dev.raspberry.core.NoticeMigration;
import dev.raspberry.core.NoticeRewrite;
import dev.raspberry.core.PinPolicy;
import dev.raspberry.core.Pkce;
import dev.raspberry.core.ReauthState;
import dev.raspberry.core.SessionCookie;
import dev.raspberry.core.UuidShape;
import dev.raspberry.core.WebRewrite;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * classes5 entry points. The dex patch calls these directly. The manifest patch adds only
 * AuthReturn, the raspberry://auth deep-link receiver.
 * JNI: Java_dev_raspberry_Raspberry_installNative (Ljava/lang/String;[I)Z
 * ports are mapped values in order 80, 443, 10000, 10123.
 */
public final class Raspberry {
    static final String PREF_UUID = "uuid";
    static final String PREF_MARKER = "raspberry.discord";
    private static final String PREF_ORIGIN = "raspberry.discord.origin";
    private static final int MAX_BODY = 16 * 1024;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private static volatile Context app;
    private static volatile Descriptor endpoint;
    private static volatile byte[] pin;
    private static volatile int config; // 0 unread, 1 ok, 2 bad
    private static volatile boolean nativeInstalled;
    private static volatile boolean noticeMigrationRetry;
    private static volatile String noticeReadyOrigin;
    private static SSLSocketFactory pinned;
    private static String pinnedHost;
    private static boolean pinLogged;

    // Main thread only: the attempt that owns the dialog, its listener, and the UI flags.
    private static final Attempt attempt = new Attempt();
    private static final ReauthState reauth = new ReauthState();
    private static Pkce proof;
    private static volatile int liveGen;
    private static long attemptResetEpoch;
    private static Activity attemptActivity;
    private static Activity resumedActivity;
    private static Application lifecycleApplication;
    private static boolean lifecycleRegistrationAttempted;

    private static Dialog dialog;
    private static Activity dialogActivity;
    private static TextView statusView;
    private static Button discordBtn;
    private static Button retryBtn;
    private static boolean failed;
    private static boolean cancelled;

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
        if (!ensureConfig(application)) {
            return "";
        }
        Descriptor current = endpoint;
        if (current == null) {
            return "";
        }
        String origin = "https://" + current.httpsAuthority();
        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(application);
            if (!prefs.getBoolean(PREF_MARKER, false) || !origin.equals(prefs.getString(PREF_ORIGIN, ""))) {
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
            if (resumedActivity == activity) {
                resumedActivity = null;
            }
            abandon();
            return false;
        }
        registerLifecycle(activity);
        // The first gate invocation precedes the sign-in Dialog, so focus is only an initial
        // lifecycle-state hint; subsequent foreground changes come from real resume/pause events.
        if (dialog == null && activity.hasWindowFocus()) {
            resumedActivity = activity;
        }
        if (liveGen != 0) {
            maybeStartExchange(liveGen);
        }
        if (!reauth.isRequired() && deviceUuid(activity).length() > 0) {
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
        String initialUuid = deviceUuid(application);
        if (initialUuid.length() == 0 || !nativeSetAuthUuid(initialUuid)) {
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

    /** Captures the Application context before the notice SDK is initialized. */
    public static void captureNoticeContext(Context context) {
        capture(context);
    }

    /** Opens a notice URL on the endpoint; target failures never fall back to LINE. */
    public static URLConnection openNoticeConnection(URL source) throws IOException {
        if (source == null) {
            throw new IOException("notice routing unavailable");
        }
        synchronized (Raspberry.class) {
            Context context = app;
            if (endpoint == null && context != null) {
                ensureConfig(context);
            }
            NoticeRewrite.Route route;
            try {
                route = NoticeRewrite.route(source.toExternalForm(), endpoint);
            } catch (IllegalArgumentException e) {
                throw new IOException("notice routing unavailable");
            }
            if (route.noticeListRequest()
                    && (endpoint == null || !noticeOrigin(endpoint).equals(noticeReadyOrigin))) {
                throw new IOException("notice routing unavailable");
            }
            URL target = route.routed() ? new URL(route.url()) : source;
            URLConnection connection = target.openConnection();
            if (route.routed()) {
                if (!(connection instanceof HttpURLConnection)) {
                    throw new IOException("notice connection unavailable");
                }
                ((HttpURLConnection) connection).setInstanceFollowRedirects(route.followsRedirects());
                if (pin != null && "https".equalsIgnoreCase(target.getProtocol())) {
                    if (!(connection instanceof HttpsURLConnection)) {
                        throw new IOException("notice TLS configuration unavailable");
                    }
                    try {
                        ((HttpsURLConnection) connection).setSSLSocketFactory(
                                pinFactory(pin, endpoint.host()));
                    } catch (Exception e) {
                        throw new IOException("notice TLS configuration unavailable");
                    }
                }
            }
            return connection;
        }
    }

    /** Runs before the notice task reads local rows or constructs remote-list cursors. */
    public static void prepareNotice() throws IOException {
        synchronized (Raspberry.class) {
            noticeReadyOrigin = null;
            Context context = app;
            if (context == null || !ensureConfig(context) || endpoint == null) {
                noticeMigrationRetry = true;
                throw new IOException("notice migration unavailable");
            }
            final String origin = noticeOrigin(endpoint);
            try {
                NoticeMigration.prepare(origin, noticeMigrationRetry, new NoticeMigration.Store() {
                    public String origin() throws IOException {
                        try {
                            return PreferenceManager.getDefaultSharedPreferences(context)
                                    .getString(NoticeMigration.ORIGIN_KEY, null);
                        } catch (RuntimeException e) {
                            throw new IOException("notice migration unavailable");
                        }
                    }

                    public void clearTables(String database, String[] tables) throws IOException {
                        clearNoticeTables(context, database, tables);
                    }

                    public void removePreferences(String preferences, String[] keys) throws IOException {
                        clearNoticePreferences(context, preferences, keys);
                    }

                    public void writeOrigin(String value) throws IOException {
                        try {
                            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                            if (!prefs.edit().putString(NoticeMigration.ORIGIN_KEY, value).commit()
                                    || !value.equals(prefs.getString(NoticeMigration.ORIGIN_KEY, null))) {
                                throw new IOException("notice migration unavailable");
                            }
                        } catch (RuntimeException e) {
                            throw new IOException("notice migration unavailable");
                        }
                    }
                });
                noticeMigrationRetry = false;
                noticeReadyOrigin = origin;
            } catch (IOException e) {
                noticeMigrationRetry = true;
                noticeReadyOrigin = null;
                throw e;
            } catch (RuntimeException e) {
                noticeMigrationRetry = true;
                noticeReadyOrigin = null;
                throw new IOException("notice migration unavailable");
            }
        }
    }

    private static String noticeOrigin(Descriptor descriptor) {
        return "https://" + descriptor.httpsAuthority();
    }

    private static void clearNoticeTables(Context context, String database, String[] tables) throws IOException {
        File path = context.getDatabasePath(database);
        if (!path.exists()) {
            return;
        }
        if (!path.isFile()) {
            throw new IOException("notice migration unavailable");
        }
        SQLiteDatabase db = null;
        try {
            db = SQLiteDatabase.openDatabase(path.getPath(), null, SQLiteDatabase.OPEN_READWRITE);
            if (db.getVersion() != 2) {
                throw new IOException("notice migration unavailable");
            }
            db.beginTransaction();
            try {
                for (String table : tables) {
                    db.delete(table, null, null);
                    if (DatabaseUtils.longForQuery(db, "SELECT COUNT(*) FROM " + table, null) != 0) {
                        throw new IOException("notice migration unavailable");
                    }
                }
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("notice migration unavailable");
        } finally {
            if (db != null) {
                db.close();
            }
        }
    }

    private static void clearNoticePreferences(Context context, String preferences, String[] keys) throws IOException {
        SharedPreferences prefs = context.getSharedPreferences(preferences, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        for (String key : keys) {
            editor.remove(key);
        }
        if (!editor.commit()) {
            throw new IOException("notice migration unavailable");
        }
        for (String key : keys) {
            if (prefs.contains(key)) {
                throw new IOException("notice migration unavailable");
            }
        }
    }

    private static native boolean installNative(String host, int[] ports);
    private static native boolean nativeSetAuthUuid(String uuid);
    private static native boolean nativeOnReauthComplete(long epoch, String uuid);

    /** Native upcall for closed session/auth reset reasons. */
    public static void onResetRequested(final long epoch, final int reason) {
        if (!reauth.beginReset(epoch, reason)) {
            return;
        }
        int gen = liveGen;
        if (gen != 0) {
            attempt.cancel(gen);
        }
        MAIN.post(new Runnable() {
            public void run() {
                if (reauth.currentEpoch() != epoch) {
                    return;
                }
                abandon();
                failed = false;
                cancelled = false;
                boolean cleaned = clearAuthStorage(app);
                reauth.markCleanupResult(epoch, cleaned);
                if (!cleaned) {
                    logStep("reset-cleanup");
                    failed = true;
                }
                Activity current = resumedActivity;
                if (current != null && !current.isFinishing() && !current.isDestroyed()) {
                    show(current);
                }
            }
        });
    }

    private static void capture(Context context) {
        if (context != null) {
            app = context;
        }
    }

    private static void registerLifecycle(final Activity first) {
        if (lifecycleApplication != null || lifecycleRegistrationAttempted) {
            return;
        }
        lifecycleRegistrationAttempted = true;
        try {
            final Application application = first.getApplication();
            application.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
                public void onActivityCreated(Activity activity, Bundle state) {}
                public void onActivityStarted(Activity activity) {}
                public void onActivityResumed(Activity activity) {
                    resumedActivity = activity;
                    if (liveGen != 0) {
                        maybeStartExchange(liveGen);
                    }
                    if (reauth.isRequired() && activity != null && !activity.isFinishing() && !activity.isDestroyed()) {
                        boolean showing = dialog != null && dialogActivity == activity && dialog.isShowing();
                        if (!showing) {
                            show(activity);
                        } else {
                            bindButtons();
                        }
                    }
                }
                public void onActivityPaused(Activity activity) {
                    if (resumedActivity == activity) {
                        resumedActivity = null;
                    }
                }
                public void onActivityStopped(Activity activity) {}
                public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
                public void onActivityDestroyed(Activity activity) {
                    if (resumedActivity == activity) {
                        resumedActivity = null;
                    }
                    if (attemptActivity == activity) {
                        if (dialogActivity == activity) {
                            dismiss();
                        }
                        abandon();
                    }
                }
            });
            lifecycleApplication = application;
            if (dialog == null && first.hasWindowFocus()) {
                resumedActivity = first;
            }
        } catch (RuntimeException e) {
            logFailure("lifecycle-register", e);
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
                logFailure("endpoint-config", e);
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
        boolean live = liveGen != 0 && attempt.live(liveGen, System.nanoTime());
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
        if (config == 2 || (reauth.isRequired() && !reauth.isCleanupVerified())) {
            return "Sign-in is unavailable.";
        }
        if (liveGen != 0 && attempt.live(liveGen, System.nanoTime())) {
            if (attempt.pending(liveGen)) {
                return "Finishing sign-in.";
            }
            if (attempt.exchanging(liveGen)) {
                return "Finishing sign-in.";
            }
            return "Waiting for the browser.";
        }
        if (cancelled) {
            return "Cancelled. Tap Discord to try again.";
        }
        if (failed) {
            return "Sign-in failed. Tap Retry.";
        }
        return "Sign in with Discord to continue.";
    }

    private static void start(Activity activity) {
        if (liveGen != 0 && attempt.live(liveGen, System.nanoTime())) {
            return;
        }
        cancelled = false;
        if (!ensureConfig(activity.getApplicationContext()) || endpoint == null) {
            setStatus("Sign-in is unavailable.");
            return;
        }
        if (!ensureCleanupForAuth(activity.getApplicationContext())) {
            failed = true;
            bindButtons();
            setStatus("Sign-in is unavailable.");
            return;
        }
        long resetEpoch = reauth.currentEpoch();
        int gen = 0;
        boolean armed = false;
        try {
            Pkce p = Pkce.generate();
            String state = Pkce.newState();
            String url = AuthUrl.start(endpoint, p.challenge, AuthUrl.RETURN, state);
            if (url == null) {
                failed = true;
                setStatus("Sign-in failed. Tap Retry.");
                return;
            }
            gen = attempt.begin(state, System.nanoTime());
            if (gen == 0) {
                failed = true;
                setStatus("Sign-in failed. Tap Retry.");
                return;
            }
            proof = p;
            liveGen = gen;
            attemptResetEpoch = resetEpoch;
            attemptActivity = activity;
            openBrowser(activity, Uri.parse(url));
            armed = true;
            failed = false;
            setStatus("Waiting for the browser.");
            bindButtons();
        } catch (Exception e) {
            logFailure("browser-start", e);
            failed = true;
            setStatus("Sign-in failed. Tap Retry.");
        } finally {
            if (!armed) {
                if (gen != 0) {
                    attempt.cancel(gen);
                }
                if (liveGen == gen) {
                    liveGen = 0;
                    proof = null;
                    attemptActivity = null;
                    attemptResetEpoch = 0;
                }
            }
        }
    }

    private static void retry(Activity activity) {
        if (liveGen != 0 && attempt.live(liveGen, System.nanoTime())) {
            abandon();
            cancelled = true;
            failed = false;
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

    /**
     * Main thread, from AuthReturn. Stages a raspberry://auth return for the live attempt;
     * anything else is ignored. The exchange still waits for the owner activity to resume.
     */
    static void onAuthReturn(Uri data) {
        int gen = liveGen;
        Pkce p = proof;
        if (gen == 0 || p == null || data == null) {
            return;
        }
        int decision = attempt.onCallback(gen, Callback.parseTarget(data.toString()), p.verifier, System.nanoTime());
        if (decision == Attempt.IGNORE) {
            return;
        }
        proof = null;
        if (decision == Attempt.FAIL) {
            logStep("callback");
            markFailed(gen);
            return;
        }
        maybeStartExchange(gen);
    }

    /** Claims the staged ticket only while its owning activity is lifecycle-resumed. */
    private static void maybeStartExchange(final int gen) {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            MAIN.post(new Runnable() {
                public void run() {
                    maybeStartExchange(gen);
                }
            });
            return;
        }
        if (gen == 0 || liveGen != gen) {
            return;
        }
        long now = System.nanoTime();
        if (!attempt.live(gen, now)) {
            logStep("exchange-expired");
            failed = true;
            liveGen = 0;
            attemptActivity = null;
            attemptResetEpoch = 0;
            setStatus("Sign-in failed. Tap Retry.");
            bindButtons();
            return;
        }
        if (!ownerOpen()) {
            abandon();
            return;
        }
        boolean foreground = ownerForeground();
        final Attempt.Exchange exchange = attempt.claimExchange(gen, now, foreground);
        if (exchange == null) {
            if (attempt.pending(gen)) {
                setStatus("Finishing sign-in.");
                bindButtons();
            }
            return;
        }
        setStatus("Finishing sign-in.");
        bindButtons();
        try {
            Thread thread = new Thread(new Runnable() {
                public void run() {
                    finishExchange(gen, exchange);
                }
            }, "raspberry-exchange");
            thread.setDaemon(true);
            thread.start();
        } catch (RuntimeException e) {
            exchange.clear();
            attempt.fail(gen);
            logFailure("exchange-start", e);
            markFailed(gen);
        }
    }

    /**
     * The HTTP call runs off the UI thread. The credential write is returned to the main thread
     * and re-checks this generation, both deadlines, and that the owner is still open.
     */
    private static void finishExchange(final int gen, final Attempt.Exchange exchange) {
        String code = null;
        try {
            code = postExchange(exchange);
        } catch (Exception e) {
            logFailure("exchange", e);
        } finally {
            exchange.clear();
        }
        final String got = code;
        MAIN.post(new Runnable() {
            public void run() {
                if (liveGen != gen) {
                    return; // cancelled, or a newer attempt owns the store
                }
                if (!reauth.canCommit(attemptResetEpoch)) {
                    attempt.cancel(gen);
                    liveGen = 0;
                    attemptActivity = null;
                    attemptResetEpoch = 0;
                    return;
                }
                if (!ownerOpen()) {
                    attempt.cancel(gen);
                    liveGen = 0;
                    attemptActivity = null;
                    attemptResetEpoch = 0;
                    return;
                }
                final long commitEpoch = attemptResetEpoch;
                if (got != null && attempt.commit(gen, System.nanoTime(), new Attempt.Writer() {
                    public boolean write() {
                        // Re-read under the attempt lock. An earlier open check must not authorize.
                        return reauth.canCommit(commitEpoch) && ownerOpen() && store(got);
                    }
                })) {
                    liveGen = 0;
                    attemptActivity = null;
                    attemptResetEpoch = 0;
                    if (app == null || deviceUuid(app).length() == 0) {
                        failed = true;
                        bindButtons();
                        return;
                    }
                    if (reauth.isRequired()) {
                        if (!reauth.canComplete(commitEpoch)
                                || !nativeOnReauthComplete(commitEpoch, got)
                                || !reauth.completeReauth(commitEpoch)) {
                            logStep("reauth-complete");
                            failed = true;
                            bindButtons();
                            return;
                        }
                    }
                    dismiss();
                    return;
                }
                attempt.fail(gen);
                markFailed(gen);
            }
        });
    }

    private static boolean ownerForeground() {
        Activity owner = attemptActivity;
        return lifecycleApplication != null && ownerOpen() && resumedActivity == owner;
    }

    /** The activity that started this attempt, still able to receive the result. */
    private static boolean ownerOpen() {
        Activity owner = attemptActivity;
        return owner != null && !owner.isFinishing() && !owner.isDestroyed();
    }

    private static boolean store(String code) {
        Context context = app;
        Descriptor current = endpoint;
        if (context == null || current == null || !UuidShape.ok(code)) {
            return false;
        }
        String origin = "https://" + current.httpsAuthority();
        // A fresh SSO must not send the previous endpoint's AV_AUTH to this origin.
        if (!SessionCookie.clear(context.getFilesDir())) {
            logStep("credential-store");
            return false;
        }
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences.Editor ed = prefs.edit();
        ed.putBoolean(PREF_MARKER, true);
        ed.putString(PREF_UUID, code);
        ed.putString(PREF_ORIGIN, origin);
        boolean stored = false;
        boolean logged = false;
        try {
            stored = ed.commit()
                    && prefs.getBoolean(PREF_MARKER, false)
                    && code.equals(prefs.getString(PREF_UUID, ""))
                    && origin.equals(prefs.getString(PREF_ORIGIN, ""));
        } catch (RuntimeException e) {
            logFailure("credential-store", e);
            logged = true;
            stored = false;
        }
        if (!stored) {
            clearLoginVerified(prefs);
            if (!logged) {
                logStep("credential-store");
            }
            return false;
        }
        return true;
    }

    private static boolean ensureCleanupForAuth(Context context) {
        if (reauth.canStartAuth()) {
            return true;
        }
        long epoch = reauth.currentEpoch();
        boolean cleaned = clearAuthStorage(context);
        reauth.markCleanupResult(epoch, cleaned);
        if (!cleaned) {
            logStep("reset-cleanup");
        }
        return reauth.canStartAuth();
    }

    private static boolean clearAuthStorage(final Context context) {
        if (context == null) {
            return false;
        }
        return ReauthState.clearNarrowly(new ReauthState.AuthStore() {
            public boolean clearCookie() {
                boolean ok = SessionCookie.clear(context.getFilesDir());
                if (!ok) {
                    logStep("cookie-clear");
                }
                return ok;
            }

            public boolean clearPrefsAndVerify() {
                try {
                    return clearLoginVerified(PreferenceManager.getDefaultSharedPreferences(context));
                } catch (RuntimeException e) {
                    logFailure("credential-clear", e);
                    return false;
                }
            }
        });
    }

    private static boolean clearLoginVerified(SharedPreferences prefs) {
        if (prefs == null) {
            return false;
        }
        try {
            SharedPreferences.Editor ed = prefs.edit();
            ed.remove(PREF_UUID);
            ed.remove(PREF_ORIGIN);
            ed.remove(PREF_MARKER);
            return ed.commit()
                    && !prefs.contains(PREF_UUID)
                    && !prefs.contains(PREF_ORIGIN)
                    && !prefs.getBoolean(PREF_MARKER, false);
        } catch (RuntimeException e) {
            // a failed commit must not leave an unverified login in memory
            logFailure("credential-clear", e);
            return false;
        }
    }

    private static String postExchange(Attempt.Exchange exchange) throws Exception {
        byte[] body = exchange.body();
        if (body == null || body.length > 4096) {
            if (body != null) {
                Arrays.fill(body, (byte) 0);
            }
            throw new IOException();
        }
        HttpURLConnection raw = null;
        byte[] response = null;
        try {
            raw = (HttpURLConnection) new URL(AuthUrl.exchange(endpoint)).openConnection();
            if (!(raw instanceof HttpsURLConnection)) {
                throw new IOException();
            }
            HttpsURLConnection conn = (HttpsURLConnection) raw;
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
                throw new IOException();
            }
            response = readCap(conn.getInputStream(), MAX_BODY, false);
            String code = Json.uniqueCode(new String(response, StandardCharsets.UTF_8));
            if (code == null) {
                throw new IOException();
            }
            return code;
        } finally {
            Arrays.fill(body, (byte) 0);
            if (response != null) {
                Arrays.fill(response, (byte) 0);
            }
            if (raw != null) {
                raw.disconnect();
            }
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
        } catch (Exception e) {
            logFailure("exchange-error-body", e);
        }
    }

    private static void markFailed(final int gen) {
        MAIN.post(new Runnable() {
            public void run() {
                if (liveGen != gen) {
                    return;
                }
                failed = true;
                liveGen = 0;
                attemptActivity = null;
                attemptResetEpoch = 0;
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
        proof = null;
        liveGen = 0;
        attemptActivity = null;
        attemptResetEpoch = 0;
        cancelled = false;
    }

    private static void logFailure(String step, Exception error) {
        Log.w("raspberry", "auth-step=" + step + " exception=" + error.getClass().getName());
    }

    private static void logStep(String step) {
        Log.w("raspberry", "auth-step=" + step);
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
}
