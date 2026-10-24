package edu.capstone.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * API Gateway (ARCHITECTURE.md steps 1-4):
 * identity + rate limit (Redis) -> fast filter (HTTP) -> cleared: forward | referred: Kafka
 * requests.suspicious, then wait on Redis verdict:<id> pushed by the Go decision engine.
 * services/tools/gateway_sim.py is the Python reference for the same flow.
 */
@RestController
public class GatewayController {

    private static final Logger log = LoggerFactory.getLogger(GatewayController.class);
    private static final List<String> FORWARD_HEADERS =
            List.of("Content-Type", "Accept", "Accept-Language", "Authorization", "Cookie", "User-Agent");
    private static final Set<String> SKIP_RESPONSE_HEADERS = Set.of("connection", "keep-alive", "transfer-encoding",
            "content-length", "content-encoding", "server", "date", "upgrade");

    private final StringRedisTemplate redis;
    private final KafkaTemplate<String, String> kafka;
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    @Value("${gateway.upstream}") String upstream;
    @Value("${gateway.fastfilter-url}") String fastFilterUrl;
    @Value("${gateway.upstream-timeout-ms}") long upstreamTimeoutMs;
    @Value("${gateway.verdict-timeout-ms}") long verdictTimeoutMs;
    @Value("${gateway.agent-deadline-ms}") long agentDeadlineMs;
    @Value("${gateway.failure-policy}") String failurePolicy;
    @Value("${gateway.max-inspect-bytes}") int maxInspectBytes;
    @Value("${gateway.trusted-proxy}") boolean trustedProxy;
    @Value("${gateway.rate-limit.max-requests}") long rateMax;
    @Value("${gateway.rate-limit.window-s}") long rateWindowS;

    public GatewayController(StringRedisTemplate redis, KafkaTemplate<String, String> kafka) {
        this.redis = redis;
        this.kafka = kafka;
    }

    @GetMapping("/_gateway/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("{\"status\":\"ok\"}");
    }

    @RequestMapping("/**")
    public ResponseEntity<byte[]> handle(HttpServletRequest req, @RequestBody(required = false) byte[] body) {
        String rid = UUID.randomUUID().toString().replace("-", "");
        long t0 = System.nanoTime();
        byte[] raw = body == null ? new byte[0] : body;
        Identity who = Identity.resolve(req, trustedProxy);
        ObjectNode ev = requestEvent(req, raw, rid, who);

        // 1. rate limit (FR-028): fixed window counter per identity in Redis
        long window = System.currentTimeMillis() / 1000 / rateWindowS;
        String rlKey = "rl:" + who.id() + ":" + window;
        Long count = redis.opsForValue().increment(rlKey);
        if (count != null && count == 1) redis.expire(rlKey, Duration.ofSeconds(rateWindowS + 1));
        if (count != null && count > rateMax) {
            publishDecision(rid, "rate_limit", "BLOCK", ev, t0);
            return bare(429, rid, "Too many requests");
        }

        // 2. fast filter
        JsonNode chk;
        try {
            chk = fastFilter(ev);
        } catch (Exception e) {                    // fast filter down: treat as referred (safer)
            log.warn("fast filter unreachable: {}", e.toString());
            chk = json.createObjectNode().put("refer", true).put("rate", 0)
                    .set("reasons", json.createArrayNode().add("fast filter unavailable"));
        }
        ev.put("endpoint", chk.path("endpoint").asText(ev.get("path").asText()));
        if (!chk.path("refer").asBoolean(true)) {
            publishDecision(rid, "fast_filter", "ALLOW", ev, t0);
            return observed(who, rid, forward(req, raw, rid));
        }

        // 3. referred: publish to Kafka, 4. wait for the decision engine's verdict
        ObjectNode ff = ev.putObject("fast_filter");
        ff.set("reasons", arrayOrEmpty(chk, "reasons"));
        ff.set("rule_ids", arrayOrEmpty(chk, "rule_ids"));
        ff.put("rules_version", chk.path("rules_version").asText(""));
        ff.put("rate", chk.path("rate").asInt(0));
        ev.set("history", arrayOrEmpty(chk, "history"));
        ev.put("deadline_ms", agentDeadlineMs);
        kafka.send("requests.suspicious", rid, ev.toString());

        String verdict;
        String got = redis.opsForList().leftPop("verdict:" + rid, Duration.ofMillis(verdictTimeoutMs));
        if (got == null) {                         // no verdict in time: failure policy (FR-036)
            verdict = "fail_closed".equals(failurePolicy) ? "BLOCK" : "FLAG";
            log.warn("no verdict for {} within {} ms, policy {}", rid, verdictTimeoutMs, failurePolicy);
        } else {
            try {
                verdict = json.readTree(got).path("verdict").asText("FLAG");
            } catch (Exception e) {
                verdict = "FLAG";
            }
        }
        if ("BLOCK".equals(verdict)) return observed(who, rid, bare(403, rid, "Forbidden"));   // UI-005
        return observed(who, rid, forward(req, raw, rid));
    }

    private ObjectNode requestEvent(HttpServletRequest req, byte[] raw, String rid, Identity who) {
        ObjectNode ev = json.createObjectNode();
        ev.put("request_id", rid);
        ev.put("ts", System.currentTimeMillis() / 1000.0);
        ev.put("method", req.getMethod());
        ev.put("path", req.getRequestURI());
        ev.put("query", req.getQueryString() == null ? "" : req.getQueryString());
        int n = Math.min(raw.length, maxInspectBytes);                     // FR-008
        ev.put("body", new String(raw, 0, n, StandardCharsets.UTF_8));
        ev.put("body_truncated", raw.length > maxInspectBytes);
        ObjectNode h = ev.putObject("headers");
        for (String name : Collections.list(req.getHeaderNames())) {
            if (!name.equalsIgnoreCase("cookie") && !name.equalsIgnoreCase("authorization")) {
                h.put(canonical(name), req.getHeader(name));
            } else {
                h.put(canonical(name), "<redacted>");                     // secrets never leave the gateway
            }
        }
        ev.put("ip", who.ip());
        ev.put("identity", who.id());
        ev.put("identity_source", who.source());
        return ev;
    }

    private static String canonical(String name) {
        String[] parts = name.toLowerCase().split("-");
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) sb.append('-');
            if (!p.isEmpty()) sb.append(Character.toUpperCase(p.charAt(0))).append(p.substring(1));
        }
        return sb.toString();
    }

    private JsonNode fastFilter(ObjectNode ev) throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(fastFilterUrl + "/check"))
                .timeout(Duration.ofMillis(500))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(ev.toString())).build();
        return json.readTree(http.send(r, HttpResponse.BodyHandlers.ofString()).body());
    }

    private void publishDecision(String rid, String route, String verdict, ObjectNode ev, long t0) {
        ObjectNode d = json.createObjectNode();
        d.put("request_id", rid);
        d.put("ts", System.currentTimeMillis() / 1000.0);
        d.put("route", route);
        d.put("verdict", verdict);
        d.putNull("score");
        d.set("request", ev);
        d.putObject("timings_ms").put("gateway", (System.nanoTime() - t0) / 1e6);
        kafka.send("decisions", rid, d.toString());
    }

    private ResponseEntity<byte[]> forward(HttpServletRequest req, byte[] raw, String rid) {
        String q = req.getQueryString();
        String url = upstream.replaceAll("/+$", "") + req.getRequestURI() + (q == null ? "" : "?" + q);
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(upstreamTimeoutMs))
                .method(req.getMethod(), raw.length == 0 ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofByteArray(raw));
        for (String hname : FORWARD_HEADERS) {
            String v = req.getHeader(hname);
            if (v != null) b.header(hname, v);
        }
        b.header("X-Request-ID", rid);
        try {
            HttpResponse<byte[]> up = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            HttpHeaders out = new HttpHeaders();
            up.headers().map().forEach((k, vs) -> {
                if (!SKIP_RESPONSE_HEADERS.contains(k.toLowerCase())) out.put(k, vs);
            });
            out.set("X-Request-ID", rid);
            return ResponseEntity.status(up.statusCode()).headers(out).body(up.body());
        } catch (Exception e) {
            log.warn("upstream unreachable for {}: {}", rid, e.toString());
            return bare(502, rid, "Bad gateway");
        }
    }

    private static ResponseEntity<byte[]> bare(int status, String rid, String text) {
        return ResponseEntity.status(status).header("X-Request-ID", rid).header("Content-Type", "text/plain")
                .body(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Tells the fast filter the response status (fire and forget) so the behaviour agent sees 4xx bursts. */
    private ResponseEntity<byte[]> observed(Identity who, String rid, ResponseEntity<byte[]> resp) {
        try {
            ObjectNode ob = json.createObjectNode();
            ob.put("identity", who.id());
            ob.put("request_id", rid);
            ob.put("status", resp.getStatusCode().value());
            HttpRequest r = HttpRequest.newBuilder(URI.create(fastFilterUrl + "/observe"))
                    .timeout(Duration.ofMillis(500))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(ob.toString())).build();
            http.sendAsync(r, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            log.debug("observe failed: {}", e.toString());
        }
        return resp;
    }

    private JsonNode arrayOrEmpty(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v != null && v.isArray() ? v : json.createArrayNode();
    }
}
