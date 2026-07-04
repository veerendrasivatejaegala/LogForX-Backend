package com.logforx.backend.controller;

import com.logforx.backend.model.*;
import com.logforx.backend.repository.*;
import com.logforx.backend.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ForensicsController {

    @Autowired
    private EvidenceRepository evidenceRepository;

    @Autowired
    private ForensicEventRepository eventRepository;

    @Autowired
    private ThreatDetectionRepository detectionRepository;

    @Autowired
    private IocRepository iocRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private LogParserService parserService;

    @Autowired
    private RiskScoreService riskScoreService;

    @Autowired
    private AIInvestigationService aiService;

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping("/evidence/list")
    public ResponseEntity<List<Evidence>> listEvidence() {
        return ResponseEntity.ok(evidenceRepository.findAll());
    }

    @PostMapping("/evidence/upload")
    public ResponseEntity<?> uploadEvidence(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "investigatorId", defaultValue = "INV-2026-9904") String investigatorId) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Empty file uploaded"));
        }

        try {
            String fileName = file.getOriginalFilename();
            byte[] fileBytes = file.getBytes();
            String content = new String(fileBytes, StandardCharsets.UTF_8);
            String lower = content.toLowerCase();
            String fileNameLower = fileName != null ? fileName.toLowerCase() : "";
            String ext = fileNameLower.contains(".") ? fileNameLower.substring(fileNameLower.lastIndexOf('.') + 1) : "log";

            // ── Structural / binary corruption ────────────────────────────
            boolean isFailed = false;
            String failReason = "";

            if (fileName != null && (fileNameLower.contains("corrupt") || fileNameLower.contains("invalid_file"))) {
                isFailed = true; failReason = "Filename indicates corruption";
            } else if (lower.startsWith("{\\rtf") || lower.contains("\\ansi") || lower.contains("\\fonttbl")) {
                isFailed = true; failReason = "RTF/binary format detected - not valid forensic text log";
            } else if (lower.contains("signature mismatch") || lower.contains("checksum mismatch")
                    || lower.contains("corrupted log") || lower.contains("corrupt log")
                    || lower.contains("corrupt file") || lower.contains("malformed xml")) {
                isFailed = true; failReason = "Corruption marker found in file content";
            } else if (file.getSize() <= 0) {
                isFailed = true; failReason = "Empty file";
            }

            // ── CSV-specific data quality validation ──────────────────────
            if (!isFailed && (ext.equals("csv") || content.contains(",") && content.contains("\n"))) {
                String[] lines = content.split("\n");
                if (lines.length > 0) {
                    String headerLine = lines[0].trim();

                    // Reject non-standard CSV headers like "csv id=..." or markdown fenced blocks
                    if (headerLine.toLowerCase().startsWith("csv id=") || headerLine.startsWith("```")) {
                        isFailed = true; failReason = "Non-standard CSV header: '" + headerLine + "'";
                    }

                    if (!isFailed) {
                        int invalidDateCount = 0, invalidIpCount = 0, missingFieldCount = 0, invalidValueCount = 0;
                        int headerCols = headerLine.split(",").length;

                        int procIdx = -1, pathIdx = -1;
                        String[] headers = headerLine.split(",");
                        for (int idx = 0; idx < headers.length; idx++) {
                            String h = headers[idx].trim().toLowerCase().replace("\"", "");
                            if (h.contains("process")) procIdx = idx;
                            else if (h.contains("path")) pathIdx = idx;
                        }

                        for (int i = 1; i < lines.length; i++) {
                            String row = lines[i].trim();
                            if (row.isEmpty()) continue;
                            String rowLower = row.toLowerCase();

                            // INVALID_DATE literal in timestamp field
                            if (rowLower.startsWith("invalid_date") || row.split(",")[0].trim().equalsIgnoreCase("INVALID_DATE")) {
                                invalidDateCount++;
                            }
                            // Impossible IP like 999.x.x.x
                            if (row.matches(".*9{3}\\.[0-9.]+.*")) {
                                invalidIpCount++;
                            }
                            // ??? as a field value
                            if (row.contains("???")) {
                                invalidValueCount++;
                            }
                            // Truncated rows (missing 2+ expected columns)
                            int rowCols = row.split(",", -1).length;
                            if (headerCols > 3 && rowCols <= (headerCols / 2)) {
                                missingFieldCount++;
                            }

                            // Invalid path or executable execution location
                            if (procIdx != -1 && pathIdx != -1 && procIdx < rowCols && pathIdx < rowCols) {
                                String[] cols = row.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                                if (procIdx < cols.length && pathIdx < cols.length) {
                                    String proc = cols[procIdx].trim().toLowerCase().replace("\"", "");
                                    String path = cols[pathIdx].trim().toLowerCase().replace("\"", "");
                                    if (path.contains("downloads") || path.contains("temp") || 
                                        (proc.endsWith(".exe") && !path.endsWith(proc))) {
                                        invalidValueCount++;
                                    }
                                }
                            }
                        }

                        int dataRows = (int) java.util.Arrays.stream(lines).filter(l -> !l.trim().isEmpty()).count() - 1;
                        if (dataRows > 0) {
                            // Fail if more than 30% of rows have data quality issues
                            double badRatio = (double)(invalidDateCount + invalidIpCount + invalidValueCount + missingFieldCount) / dataRows;
                            if (badRatio > 0.3) {
                                isFailed = true;
                                failReason = String.format("CSV data quality failure: %d invalid timestamps, %d invalid IPs, %d invalid values, %d truncated rows out of %d total rows (%.0f%% bad)",
                                    invalidDateCount, invalidIpCount, invalidValueCount, missingFieldCount, dataRows, badRatio * 100);
                            }
                        }
                    }
                }
            }

            // ── Unstructured ALERT/DETECTION log format ───────────────────
            // These are non-parseable alert dump formats, not standard syslog/CSV
            if (!isFailed && ext.equals("log")) {
                boolean hasAlertMarker = content.contains("] ALERT\n") || content.contains("] DETECTION\n") || content.contains("] ALERT\r\n") || content.contains("] DETECTION\r\n");
                boolean hasCategoryKey = content.contains("Category      :") || (content.contains("Category:") && content.contains("MITRE ATT&CK  :"));
                if (hasAlertMarker && hasCategoryKey) {
                    isFailed = true; failReason = "Unstructured ALERT/DETECTION dump format — not a parseable syslog. Convert to CSV or standard syslog format.";
                }
            }

            if (!isFailed && ext.equals("csv")) {
                if (lower.contains("type,value,description,severity,mitre att&ck") || lower.contains("\"threat type\",\"status\",\"description\"")) {
                    isFailed = true; failReason = "Cannot ingest exported alert logs as evidence to prevent detection feedback loops.";
                }
            }

            System.out.println("=== FORENSIC INGEST UPLOAD ===");
            System.out.println("File Name   : " + fileName);
            System.out.println("File Size   : " + file.getSize());
            System.out.println("Extension   : " + ext);
            System.out.println("isFailed    : " + isFailed);
            System.out.println("Fail Reason : " + (isFailed ? failReason : "N/A"));
            System.out.println("Content[200]: " + lower.substring(0, Math.min(200, lower.length())));
            System.out.println("=============================");


            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(fileBytes);
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            String sha256 = sb.toString();

            List<Evidence> allEv = evidenceRepository.findAll();
            for (Evidence ev : allEv) {
                if (ev.getHash().equals(sha256)) {
                    if (isFailed && !"FAILED".equals(ev.getStatus())) {
                        ev.setStatus("FAILED");
                        evidenceRepository.save(ev);
                    }
                    return ResponseEntity.ok(ev);
                }
            }

            String fileType = "log";
            if (fileName != null) {
                int dotIdx = fileName.lastIndexOf('.');
                if (dotIdx != -1) {
                    fileType = fileName.substring(dotIdx + 1);
                }
            }

            String status = isFailed ? "FAILED" : "PARSED";

            Evidence evidence = new Evidence(null, fileName, sha256, LocalDateTime.now(), fileType, status, investigatorId, file.getSize());
            evidenceRepository.save(evidence);

            if (!isFailed) {
                parserService.parseEvidence(evidence, new ByteArrayInputStream(fileBytes));
                auditLogService.logAction("EVIDENCE_UPLOAD", investigatorId, "Uploaded file: " + fileName + " (Hash: " + sha256.substring(0, 8) + "...)");
            } else {
                auditLogService.logAction("INTEGRITY_CHECK_FAILED", investigatorId, "File failed integrity verification: " + fileName + " (Size: " + file.getSize() + " bytes)");
            }

            return ResponseEntity.ok(evidence);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Error uploading file: " + e.getMessage()));
        }
    }

    @GetMapping("/timeline")
    public ResponseEntity<List<ForensicEvent>> getTimeline() {
        return ResponseEntity.ok(eventRepository.findAllByOrderByTimestampAsc());
    }

    @GetMapping("/detections")
    public ResponseEntity<List<ThreatDetection>> getDetections() {
        return ResponseEntity.ok(detectionRepository.findAll());
    }

    @GetMapping("/ioc")
    public ResponseEntity<List<Ioc>> getIocs() {
        return ResponseEntity.ok(iocRepository.findAll());
    }

    @GetMapping("/risk")
    public ResponseEntity<Map<String, Object>> getRiskScore() {
        return ResponseEntity.ok(riskScoreService.calculateRiskScore());
    }

    @GetMapping("/ai/investigate")
    public ResponseEntity<Map<String, Object>> getAiInvestigation() {
        return ResponseEntity.ok(aiService.getInvestigationCopilotData());
    }

    @GetMapping("/audits")
    public ResponseEntity<List<AuditLog>> getAuditLogs() {
        return ResponseEntity.ok(auditLogService.getAuditLogs());
    }

    @GetMapping("/attack-graph")
    public ResponseEntity<Map<String, Object>> getAttackGraph() {
        List<ThreatDetection> detections = detectionRepository.findAll();
        
        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> links = new ArrayList<>();

        nodes.add(Map.of("id", "1", "label", "Initial Log Entry", "type", "System", "severity", "Low", "description", "Log ingestion monitor activated."));
        
        if (detections.isEmpty()) {
            Map<String, Object> graph = new HashMap<>();
            graph.put("nodes", nodes);
            graph.put("links", links);
            return ResponseEntity.ok(graph);
        }

        int nodeId = 2;
        String prevId = "1";
        
        for (ThreatDetection det : detections) {
            String idStr = String.valueOf(nodeId);
            String nodeType = "Alert";
            if (det.getThreatType().contains("Brute Force")) nodeType = "Access";
            else if (det.getThreatType().contains("Malicious")) nodeType = "Execution";
            else if (det.getThreatType().contains("Persistence")) nodeType = "Persistence";
            else if (det.getThreatType().contains("Control")) nodeType = "Network";
            else if (det.getThreatType().contains("Exfiltration")) nodeType = "Exfiltration";
            
            nodes.add(Map.of(
                "id", idStr,
                "label", det.getThreatType(),
                "type", nodeType,
                "severity", det.getSeverity(),
                "description", det.getDescription()
            ));
            
            links.add(Map.of(
                "source", prevId,
                "target", idStr
            ));
            
            prevId = idStr;
            nodeId++;
        }

        Map<String, Object> graph = new HashMap<>();
        graph.put("nodes", nodes);
        graph.put("links", links);
        return ResponseEntity.ok(graph);
    }

    @GetMapping("/reports")
    public ResponseEntity<?> getReports() {
        Map<String, Object> risk = riskScoreService.calculateRiskScore();
        List<Evidence> evidence = evidenceRepository.findAll();
        List<ThreatDetection> detections = detectionRepository.findAll();
        
        Map<String, Object> report = new HashMap<>();
        report.put("caseName", "CASE-2026-LOGFORX");
        report.put("generatedAt", LocalDateTime.now().toString());
        report.put("investigator", "John Doe");
        report.put("riskScore", risk.get("score"));
        report.put("riskLevel", risk.get("level"));
        report.put("totalEvidence", evidence.size());
        report.put("totalAlerts", detections.size());
        report.put("evidenceList", evidence);
        report.put("alertList", detections);
        
        return ResponseEntity.ok(report);
    }

    @PostMapping("/settings/reset")
    public ResponseEntity<?> resetDatabase() {
        eventRepository.deleteAll();
        detectionRepository.deleteAll();
        iocRepository.deleteAll();
        evidenceRepository.deleteAll();
        auditLogRepository.deleteAll();
        
        auditLogService.logAction("SYSTEM_RESET", "SYSTEM", "Database cleared. Environment reset.");
        return ResponseEntity.ok(Map.of("message", "All forensic data has been cleared"));
    }

    @PostMapping("/settings/seed")
    public ResponseEntity<?> seedDatabase() {
        // Clear first
        eventRepository.deleteAll();
        detectionRepository.deleteAll();
        iocRepository.deleteAll();
        evidenceRepository.deleteAll();
        auditLogRepository.deleteAll();
        
        Evidence file1 = new Evidence(null, "windows_event_log_4624.evtx", "a2b4c6d8e0f1g2h3i4j5k6l7m8n9o0p1", LocalDateTime.now().minusHours(4), "evtx", "PARSED", "INV-2026-9904", 45032L);
        Evidence file2 = new Evidence(null, "linux_syslog.log", "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7", LocalDateTime.now().minusHours(3), "log", "PARSED", "INV-2026-9904", 12891L);
        
        evidenceRepository.save(file1);
        evidenceRepository.save(file2);
        
        parserService.parseEvidence(file1, new ByteArrayInputStream(new byte[0]));
        parserService.parseEvidence(file2, new ByteArrayInputStream(new byte[0]));
        
        auditLogService.logAction("DATABASE_SEEDED", "SYSTEM", "Default forensic demonstration logs pre-loaded.");
        return ResponseEntity.ok(Map.of("message", "Forensic database pre-seeded with sample logs successfully."));
    }
}
