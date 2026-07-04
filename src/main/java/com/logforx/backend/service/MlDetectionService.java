package com.logforx.backend.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.logforx.backend.dto.MlIntegrityResult;
import com.logforx.backend.dto.MlThreatResult;
import com.logforx.backend.model.ForensicEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class MlDetectionService {

    @Value("${logforx.ml.url:http://localhost:8090}")
    private String mlServiceUrl;

    @Value("${logforx.ml.enabled:true}")
    private boolean mlEnabled;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    private JsonNode config;
    private static final Pattern PORT_PATTERN = Pattern.compile("dpt=(\\d+)", Pattern.CASE_INSENSITIVE);

    private JsonNode getConfig() {
        if (config == null) {
            try (InputStream is = new ClassPathResource("ml/config.json").getInputStream()) {
                config = mapper.readTree(is);
            } catch (Exception e) {
                config = mapper.createObjectNode();
            }
        }
        return config;
    }

    public MlIntegrityResult checkIntegrity(String content, String filename) {
        if (mlEnabled) {
            MlIntegrityResult remote = callRemoteIntegrity(content, filename);
            if (remote != null) return remote;
        }
        return embeddedIntegrityCheck(content, filename);
    }

    public List<MlThreatResult> analyzeThreats(List<ForensicEvent> events) {
        if (mlEnabled) {
            List<MlThreatResult> remote = callRemoteThreats(events);
            if (remote != null) return remote;
        }
        return embeddedThreatAnalysis(events);
    }

    private MlIntegrityResult callRemoteIntegrity(String content, String filename) {
        try {
            Map<String, String> body = Map.of("content", content, "filename", filename != null ? filename : "");
            String json = mapper.writeValueAsString(body);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(mlServiceUrl + "/predict/integrity"))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonNode node = mapper.readTree(response.body());
                return new MlIntegrityResult(
                        node.path("prediction").asText(),
                        node.path("passScore").asDouble(),
                        node.path("failScore").asDouble(),
                        node.path("source").asText("ml")
                );
            }
        } catch (Exception ignored) {}
        return null;
    }

    private List<MlThreatResult> callRemoteThreats(List<ForensicEvent> events) {
        try {
            List<Map<String, Object>> payload = new ArrayList<>();
            for (ForensicEvent e : events) {
                Map<String, Object> ev = new LinkedHashMap<>();
                if (e.getTimestamp() != null) ev.put("timestamp", e.getTimestamp().toString());
                ev.put("eventType", e.getEventType());
                ev.put("severity", e.getSeverity());
                ev.put("source", e.getSource());
                ev.put("username", e.getUsername());
                ev.put("ipAddress", e.getIpAddress());
                ev.put("action", e.getAction());
                ev.put("payloadDetails", e.getPayloadDetails());
                payload.add(ev);
            }
            Map<String, Object> body = Map.of("events", payload);
            String json = mapper.writeValueAsString(body);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(mlServiceUrl + "/predict/threats"))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonNode node = mapper.readTree(response.body());
                List<MlThreatResult> results = new ArrayList<>();
                for (JsonNode det : node.path("detections")) {
                    results.add(new MlThreatResult(
                            det.path("threatKey").asText(),
                            det.path("threatType").asText(),
                            det.path("severity").asText(),
                            det.path("confidence").asDouble(),
                            det.path("mitreTechnique").asText(),
                            det.path("description").asText(),
                            det.path("detectionSource").asText("ml")
                    ));
                }
                return results;
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ── Embedded fallback (works without Python service) ─────────────────

    public MlIntegrityResult embeddedIntegrityCheck(String content, String filename) {
        String lower = content.toLowerCase();
        String fn = filename != null ? filename.toLowerCase() : "";
        String[] lines = content.split("\n");
        int lineCount = 0, invalidDate = 0, invalidIp = 0, invalidVal = 0, truncated = 0, invalidPath = 0;
        int headerCols = lines.length > 0 ? lines[0].split(",").length : 0;

        int procIdx = -1, pathIdx = -1;
        if (lines.length > 0) {
            String[] headers = lines[0].split(",");
            for (int idx = 0; idx < headers.length; idx++) {
                String h = headers[idx].trim().toLowerCase().replace("\"", "");
                if (h.contains("process")) procIdx = idx;
                else if (h.contains("path")) pathIdx = idx;
            }
        }

        for (String line : lines) {
            if (line.isBlank()) continue;
            lineCount++;
            String ll = line.toLowerCase();
            if (ll.contains("invalid_date")) invalidDate++;
            if (line.matches(".*9{3}\\.[0-9.]+.*")) invalidIp++;
            if (line.contains("???")) invalidVal++;
            if (!content.trim().startsWith("{") && !content.trim().startsWith("[") && headerCols > 3 && line.split(",").length <= headerCols / 2) truncated++;

            if (procIdx != -1 && pathIdx != -1) {
                String[] cols = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                if (procIdx < cols.length && pathIdx < cols.length) {
                    String proc = cols[procIdx].trim().toLowerCase().replace("\"", "");
                    String path = cols[pathIdx].trim().toLowerCase().replace("\"", "");
                    if (path.contains("downloads") || path.contains("temp") || 
                        (proc.endsWith(".exe") && !path.endsWith(proc))) {
                        invalidPath++;
                    }
                }
            }
        }
        int dataRows = Math.max(lineCount - 1, 1);
        double badRatio = (double) (invalidDate + invalidIp + invalidVal + truncated + invalidPath) / dataRows;

        boolean fail = fn.contains("corrupt")
                || lower.startsWith("{\\rtf") || lower.contains("\\fonttbl")
                || lower.contains("corrupt") || lower.contains("checksum mismatch")
                || badRatio > 0.3
                || (lower.contains("] alert") && lower.contains("mitre"));

        double passScore = fail ? Math.max(0.05, 1.0 - badRatio) : Math.min(0.95, 0.7 + (1.0 - badRatio) * 0.3);
        return new MlIntegrityResult(fail ? "FAIL" : "PASS", passScore, 1.0 - passScore, "embedded");
    }

    public List<MlThreatResult> embeddedThreatAnalysis(List<ForensicEvent> events) {
        Map<String, Integer> failedByIp = new HashMap<>();
        Map<String, Set<String>> portsByIp = new HashMap<>();
        Map<String, List<Double>> rpsByIp = new HashMap<>();
        StringBuilder corpus = new StringBuilder();

        for (ForensicEvent e : events) {
            String ip = e.getIpAddress() != null ? e.getIpAddress() : "unknown";
            String action = e.getAction() != null ? e.getAction().toLowerCase() : "";
            String payload = e.getPayloadDetails() != null ? e.getPayloadDetails().toLowerCase() : "";
            String combined = action + " " + payload;
            corpus.append(combined).append(" ");

            if (isFailedLogin(e)) {
                failedByIp.merge(ip, 1, Integer::sum);
            }
            Matcher m = PORT_PATTERN.matcher(combined);
            while (m.find()) {
                portsByIp.computeIfAbsent(ip, k -> new HashSet<>()).add(m.group(1));
            }
            double rps = extractRps(combined);
            if (rps > 0) {
                rpsByIp.computeIfAbsent(ip, k -> new ArrayList<>()).add(rps);
            }
        }

        int maxFailed = failedByIp.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        int maxPorts = portsByIp.values().stream().mapToInt(Set::size).max().orElse(0);
        double maxRps = rpsByIp.values().stream().flatMap(List::stream).mapToDouble(Double::doubleValue).max().orElse(0);
        String text = corpus.toString();

        JsonNode thresholds = getConfig().path("threat").path("behavioral_thresholds");
        int bfThreshold = thresholds.path("bruteforce_failed_logins").asInt(3);
        double ddosRps = thresholds.path("ddos_rps").asDouble(3000);
        double dosRps = thresholds.path("dos_rps").asDouble(1500);
        int portThreshold = thresholds.path("port_scan_unique_ports").asInt(2);

        List<MlThreatResult> results = new ArrayList<>();
        if (maxFailed >= bfThreshold || text.contains("brute")) {
            results.add(build("bruteforce", 0.85, "embedded"));
        }
        if (maxRps >= ddosRps || text.contains("ddos") || text.contains("traffic_spike") || text.contains("syn flood")) {
            results.add(build("ddos", 0.88, "embedded"));
        }
        if (maxRps >= dosRps && maxRps < ddosRps) {
            results.add(build("dos", 0.75, "embedded"));
        }
        if (maxPorts >= portThreshold || text.contains("nmap") || text.contains("port scan")) {
            results.add(build("port_scan", 0.80, "embedded"));
        }
        if (text.contains("spyware") || text.contains("mimikatz") || text.contains("keylogger") || text.contains("lsass")) {
            results.add(build("spyware", 0.86, "embedded"));
        }
        if (text.contains("adware") || text.contains("pua") || text.contains("browser hijack")) {
            results.add(build("adware", 0.72, "embedded"));
        }
        if (text.contains("phishing") || text.contains("spearphish") || text.contains("malicious attachment")) {
            results.add(build("phishing", 0.78, "embedded"));
        }
        if (text.contains("wget http") || text.contains("curl http") || text.contains("powershell")
                || text.contains("chmod +x") || text.contains("malware execution")) {
            results.add(build("malware_execution", 0.87, "embedded"));
        }
        if (text.contains("unauthorized") || text.contains("403 forbidden") || text.contains("permission denied")) {
            results.add(build("unauthorized_access", 0.77, "embedded"));
        }
        return results;
    }

    private boolean isFailedLogin(ForensicEvent e) {
        String action = e.getAction() != null ? e.getAction().toLowerCase() : "";
        String payload = e.getPayloadDetails() != null ? e.getPayloadDetails().toLowerCase() : "";
        String combined = action + " " + payload;
        if (combined.contains("success")) return false;
        return combined.contains("failed login") || combined.contains("failed password")
                || combined.contains("invalid user") || combined.contains("authentication failure")
                || combined.contains("login_attempt") || (combined.contains("failed") && combined.contains("login"));
    }

    private double extractRps(String text) {
        Matcher m = Pattern.compile("(\\d{3,5})").matcher(text);
        while (m.find()) {
            double val = Double.parseDouble(m.group(1));
            if (val >= 500 && val <= 100000) return val;
        }
        return 0;
    }

    private MlThreatResult build(String key, double confidence, String source) {
        JsonNode threat = getConfig().path("threat");
        return new MlThreatResult(
                key,
                threat.path("threat_display").path(key).asText(key),
                threat.path("threat_severity").path(key).asText("High"),
                confidence,
                threat.path("threat_mitre").path(key).asText(""),
                "ML engine detected " + threat.path("threat_display").path(key).asText(key)
                        + " with " + Math.round(confidence * 100) + "% confidence.",
                source
        );
    }
}
