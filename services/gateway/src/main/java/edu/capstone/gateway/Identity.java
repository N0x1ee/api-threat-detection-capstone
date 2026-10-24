package edu.capstone.gateway;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/** FR-009: session cookie > bearer token > API key > source IP. Secrets are hashed (SEC-025).
 *  Client identity headers are ignored unless trusted-proxy mode is on (ADD-32). Mirrors server.py. */
public record Identity(String id, String source, String ip) {

    static final List<String> SESSION_COOKIES = List.of("session", "sessionid", "PHPSESSID", "JSESSIONID", "connect.sid");

    static String digest(String v) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(v.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Identity resolve(HttpServletRequest req, boolean trustedProxy) {
        String ip = req.getRemoteAddr() == null ? "0.0.0.0" : req.getRemoteAddr();
        String xff = req.getHeader("X-Forwarded-For");
        if (trustedProxy && xff != null && !xff.isBlank()) ip = xff.split(",")[0].trim();
        String xuid = req.getHeader("X-User-Id");
        if (trustedProxy && xuid != null && !xuid.isBlank()) return new Identity("user:" + digest(xuid), "trusted_header", ip);
        if (req.getCookies() != null) {
            for (String name : SESSION_COOKIES) {
                for (Cookie c : req.getCookies()) {
                    if (c.getName().equals(name) && !c.getValue().isEmpty())
                        return new Identity("sess:" + digest(c.getValue()), "session_cookie", ip);
                }
            }
        }
        String auth = req.getHeader("Authorization");
        if (auth != null && auth.toLowerCase().startsWith("bearer ") && auth.length() > 7)
            return new Identity("tok:" + digest(auth.substring(7).trim()), "bearer_token", ip);
        String key = req.getHeader("X-API-Key");
        if (key != null && !key.isBlank()) return new Identity("key:" + digest(key), "api_key", ip);
        return new Identity("ip:" + ip, "source_ip", ip);
    }
}
