package dev.raspberry.core;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** Strict authority-only routing for the notice SDK's HTTP requests. */
public final class NoticeRewrite {
    private NoticeRewrite() {}

    public static Route route(String raw, Descriptor endpoint) {
        URI uri = parse(raw);
        String authority = uri.getRawAuthority();
        String host = uri.getHost();
        if (authority.charAt(0) == '[') {
            return new Route(raw, false);
        }
        host = host.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.length() == 0 || host.endsWith(".")) {
            throw new IllegalArgumentException("notice host");
        }
        if (!allowed(host)) {
            return new Route(raw, false);
        }
        boolean https = uri.getScheme().equalsIgnoreCase("https");
        int defaultPort = https ? 443 : 80;
        int port = uri.getPort();
        if (port != -1 && port != defaultPort) {
            throw new IllegalArgumentException("notice port");
        }
        if (endpoint == null) {
            throw new IllegalArgumentException("notice endpoint");
        }
        int mapped = endpoint.port(defaultPort);
        String targetAuthority = endpoint.host() + (mapped == defaultPort ? "" : ":" + mapped);
        int authorityStart = uri.getScheme().length() + 3;
        int authorityEnd = authorityStart + authority.length();
        if (authorityEnd > raw.length() || !authority.equals(raw.substring(authorityStart, authorityEnd))) {
            throw new IllegalArgumentException("notice authority");
        }
        String rewritten = raw.substring(0, authorityStart) + targetAuthority + raw.substring(authorityEnd);
        return new Route(rewritten, true, "/v1/lineplay/android".equals(uri.getRawPath()));
    }

    private static URI parse(String raw) {
        if (raw == null || raw.length() == 0) {
            throw new IllegalArgumentException("notice url");
        }
        URI uri;
        try {
            uri = new URI(raw);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("notice url");
        }
        String scheme = uri.getScheme();
        boolean https = scheme != null && scheme.equalsIgnoreCase("https");
        if ((!https && (scheme == null || !scheme.equalsIgnoreCase("http"))) || !uri.isAbsolute() || uri.isOpaque()) {
            throw new IllegalArgumentException("notice url");
        }
        String authority = uri.getRawAuthority();
        String host = uri.getHost();
        int port = uri.getPort();
        if (authority == null || authority.length() == 0 || uri.getRawUserInfo() != null
                || host == null || host.length() == 0) {
            throw new IllegalArgumentException("notice authority");
        }
        if (authority.endsWith(":") || port < -1 || port == 0 || port > 65535) {
            throw new IllegalArgumentException("notice port");
        }
        return uri;
    }

    private static boolean allowed(String host) {
        if (host == null) {
            return false;
        }
        if (WebRewrite.allowed(host)) {
            return true;
        }
        return family(host, ".play.naver.jp")
                || family(host, ".play.naver.net")
                || family(host, ".line-scdn.net")
                || family(host, ".line-apps.com")
                || family(host, ".line.naver.jp");
    }

    private static boolean family(String host, String suffix) {
        return host.equals(suffix.substring(1)) || host.endsWith(suffix);
    }

    public static final class Route {
        private final String url;
        private final boolean routed;
        private final boolean noticeListRequest;

        private Route(String url, boolean routed, boolean noticeListRequest) {
            this.url = url;
            this.routed = routed;
            this.noticeListRequest = noticeListRequest;
        }

        private Route(String url, boolean routed) {
            this(url, routed, false);
        }

        public String url() {
            return url;
        }

        public boolean routed() {
            return routed;
        }

        public boolean followsRedirects() {
            return !routed;
        }

        public boolean noticeListRequest() {
            return routed && noticeListRequest;
        }
    }
}
