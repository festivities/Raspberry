package dev.raspberry.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/** S256 PKCE. Challenge is base64url(SHA-256(verifier ASCII)), matching the stub. */
public final class Pkce {
    public final String verifier;
    public final String challenge;

    private Pkce(String verifier, String challenge) {
        this.verifier = verifier;
        this.challenge = challenge;
    }

    public static Pkce generate() {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        return of(raw);
    }

    public static Pkce of(byte[] raw) {
        if (raw == null || raw.length != 32) {
            throw new IllegalArgumentException("pkce");
        }
        String verifier = B64Url.enc(raw);
        return new Pkce(verifier, challenge(verifier));
    }

    public static String challenge(String verifier) {
        if (verifier == null) {
            throw new IllegalArgumentException("pkce");
        }
        try {
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return B64Url.enc(sum);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("pkce");
        }
    }

    public static String newState() {
        byte[] raw = new byte[16];
        new SecureRandom().nextBytes(raw);
        return B64Url.enc(raw);
    }
}
