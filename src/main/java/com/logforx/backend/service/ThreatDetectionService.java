package com.logforx.backend.service;

import com.logforx.backend.model.ForensicEvent;
import com.logforx.backend.model.ThreatDetection;
import com.logforx.backend.model.Ioc;
import com.logforx.backend.repository.ThreatDetectionRepository;
import com.logforx.backend.repository.IocRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ThreatDetectionService {

    @Autowired
    private ThreatDetectionRepository detectionRepository;

    @Autowired
    private IocRepository iocRepository;

    public void analyzeEvents(List<ForensicEvent> events) {
        int failedLoginCount = 0;
        int portScanCount = 0;
        int httpFloodCount = 0;

        for (ForensicEvent event : events) {
            String action  = event.getAction() != null  ? event.getAction().toLowerCase()  : "";
            String payload = event.getPayloadDetails() != null ? event.getPayloadDetails().toLowerCase() : "";
            String source  = event.getSource() != null  ? event.getSource().toLowerCase()  : "";
            String ip      = event.getIpAddress() != null ? event.getIpAddress() : "unknown";
            String user    = event.getUsername() != null ? event.getUsername() : "unknown";

            // ── RULE 1: Brute Force Attack ────────────────────────────────
            if (action.contains("failed login") || action.contains("failed ssh")
                    || action.contains("invalid user") || action.contains("authentication failure")
                    || payload.contains("failed password") || payload.contains("invalid user")) {
                failedLoginCount++;
                if (failedLoginCount >= 3) {
                    createAlert("Brute Force Attack", "Critical",
                        "Multiple consecutive failed login attempts from " + ip + " targeting user '" + user + "'. " +
                        "Pattern matches automated credential stuffing (MITRE T1110.001).",
                        "T1110.001 (Brute Force: Password Guessing)");
                    createIoc("IP", ip, "Brute Force Source IP");
                }
            }

            // ── RULE 2: Dictionary Attack ─────────────────────────────────
            if ((action.contains("failed login") || payload.contains("invalid password"))
                    && (payload.contains("wordlist") || payload.contains("hydra")
                        || payload.contains("medusa") || payload.contains("john")
                        || payload.contains("dictionary"))) {
                createAlert("Dictionary Attack", "High",
                    "Automated dictionary-based login tool detected targeting " + ip + ". " +
                    "Tool signatures found in session payload.",
                    "T1110.002 (Brute Force: Password Cracking)");
            }

            // ── RULE 3: Malware Execution ─────────────────────────────────
            if ((payload.contains("powershell") && (payload.contains("downloadstring") || payload.contains("iex") || payload.contains("invoke-expression")))
                    || payload.contains("wget http") || payload.contains("curl http")
                    || payload.contains("chmod +x") || payload.contains(".sh;")
                    || payload.contains("base64 -d") || payload.contains("bash -c")) {
                createAlert("Malware Execution", "Critical",
                    "Suspicious executable/script download-and-execute pattern detected on host " + source + ". " +
                    "Possible dropper or stager for malware payload delivery.",
                    "T1059 (Command and Scripting Interpreter)");
                extractAndCreateUrlIoc(payload);
            }

            // ── RULE 4: Trojan / Backdoor ─────────────────────────────────
            if (payload.contains("backdoor") || payload.contains("/dev/tcp/")
                    || payload.contains("reverse shell") || payload.contains("nc -e")
                    || payload.contains("netcat") || payload.contains("bash -i")
                    || payload.contains("0>&1") || payload.contains("meterpreter")) {
                createAlert("Trojan / Backdoor Detected", "Critical",
                    "Reverse shell or trojan backdoor communication channel established from host " + source + " to " + ip + ". " +
                    "Possible persistent remote access implant active.",
                    "T1571 (Non-Standard Port) / T1059.004 (Unix Shell)");
                createIoc("IP", ip, "Backdoor C2 Target IP");
            }

            // ── RULE 5: Command Execution / RCE ──────────────────────────
            if (payload.contains("; ls") || payload.contains("; id") || payload.contains("; whoami")
                    || payload.contains("cmd=") || payload.contains("exec(")
                    || payload.contains("system(") || payload.contains("passthru(")
                    || action.contains("command execution") || action.contains("rce")) {
                createAlert("Remote Command Execution", "Critical",
                    "Arbitrary OS command injection or RCE pattern detected in request payload from " + ip + ". " +
                    "System command output leakage suspected.",
                    "T1203 (Exploitation for Client Execution) / T1059");
                createIoc("IP", ip, "RCE Source IP");
            }

            // ── RULE 6: SQL / Code Injection ─────────────────────────────
            if (payload.contains("' or '1'='1") || payload.contains("' or 1=1")
                    || payload.contains("union select") || payload.contains("drop table")
                    || payload.contains("insert into") && payload.contains("--")
                    || payload.contains("<script>") || payload.contains("onerror=")
                    || payload.contains("javascript:") || action.contains("injection")) {
                createAlert("Injection Attack", "Critical",
                    "SQL Injection or XSS payload detected in application layer from " + ip + ". " +
                    "Attacker attempting to manipulate backend database or execute client-side scripts.",
                    "T1190 (Exploit Public-Facing Application)");
                createIoc("IP", ip, "Injection Attack Source IP");
            }

            // ── RULE 7: Port Scanning ─────────────────────────────────────
            if (payload.contains("syn scan") || payload.contains("nmap")
                    || payload.contains("port scan") || payload.contains("dpt=22")
                    || payload.contains("dpt=3306") || payload.contains("dpt=443")
                    || (payload.contains("spt=") && payload.contains("dpt=") && payload.contains("proto=tcp"))
                    || action.contains("port scan")) {
                portScanCount++;
                if (portScanCount >= 1) {
                    createAlert("Port Scanning", "High",
                        "Network reconnaissance / port scanning activity detected from " + ip + ". " +
                        "Multiple TCP SYN probes across sequential ports identified.",
                        "T1046 (Network Service Discovery)");
                    createIoc("IP", ip, "Port Scan Source IP");
                }
            }

            // ── RULE 8: DDoS / DoS ───────────────────────────────────────
            if (payload.contains("ddos") || payload.contains("flood")
                    || payload.contains("syn flood") || payload.contains("http flood")
                    || payload.contains("amplification") || action.contains("ddos")
                    || action.contains("dos attack") || action.contains("flood")) {
                httpFloodCount++;
                createAlert("DDoS / DoS Attack", "Critical",
                    "Distributed Denial-of-Service flood pattern detected targeting " + source + ". " +
                    "High-volume SYN/HTTP flood originating from " + ip + ".",
                    "T1498 (Network Denial of Service)");
                createIoc("IP", ip, "DDoS Attack Source IP");
            }

            // ── RULE 9: Phishing ──────────────────────────────────────────
            if (payload.contains("phishing") || payload.contains("credential harvest")
                    || payload.contains("fake login") || payload.contains("spearphish")
                    || payload.contains("suspicious email") || payload.contains("malicious attachment")
                    || action.contains("phishing")) {
                createAlert("Phishing Attack", "High",
                    "Phishing attempt or credential harvesting activity identified targeting user '" + user + "'. " +
                    "Suspicious email link or attachment involved.",
                    "T1566 (Phishing)");
            }

            // ── RULE 10: Unauthorized Access ──────────────────────────────
            if (action.contains("unauthorized") || action.contains("access denied")
                    || payload.contains("unauthorized access") || payload.contains("403 forbidden")
                    || payload.contains("permission denied") || payload.contains("access violation")) {
                createAlert("Unauthorized Access Attempt", "High",
                    "Unauthorized resource access attempt detected from " + ip + " by user '" + user + "'. " +
                    "Possible privilege abuse or lateral movement.",
                    "T1078 (Valid Accounts) / T1021 (Remote Services)");
                createIoc("IP", ip, "Unauthorized Access Source IP");
            }

            // ── RULE 11: Privilege Escalation ─────────────────────────────
            if (action.contains("privilege escalation") || action.contains("sudo")
                    || payload.contains("sudo su") || payload.contains("sudo bash")
                    || payload.contains("setuid") || payload.contains("pkexec")
                    || (action.contains("successful login") && event.getSeverity() != null
                        && event.getSeverity().equalsIgnoreCase("high"))) {
                createAlert("Privilege Escalation", "High",
                    "Privilege escalation detected: user '" + user + "' elevated to root/admin on " + source + ". " +
                    "Lateral movement or post-exploitation activity may follow.",
                    "T1078 (Valid Accounts) / T1548 (Abuse Elevation Control Mechanism)");
            }

            // ── RULE 12: Spyware / Data Harvesting ────────────────────────
            if (payload.contains("keylogger") || payload.contains("screen capture")
                    || payload.contains("clipboard") || payload.contains("credential dump")
                    || payload.contains("mimikatz") || payload.contains("lsass")
                    || payload.contains("spyware") || action.contains("spyware")) {
                createAlert("Spyware / Credential Harvesting", "Critical",
                    "Credential harvesting or spyware activity detected on host " + source + ". " +
                    "Memory dumping or keylogging tools may be running.",
                    "T1003 (OS Credential Dumping)");
            }

            // ── RULE 13: Adware / PUA ─────────────────────────────────────
            if (payload.contains("adware") || payload.contains("potentially unwanted")
                    || payload.contains("pua") || payload.contains("browser hijack")
                    || action.contains("adware")) {
                createAlert("Adware / PUA Detected", "Medium",
                    "Potentially Unwanted Application (adware) activity identified. " +
                    "Browser hijacking or ad-injection components may be active on " + source + ".",
                    "T1176 (Browser Extensions)");
            }

            // ── RULE 14: Malware (Generic) ────────────────────────────────
            if (payload.contains("trojan") || payload.contains("ransomware")
                    || payload.contains("virus") || payload.contains("worm")
                    || payload.contains("rootkit") || payload.contains("malware")
                    || action.contains("malware detected")) {
                createAlert("Malware Detected", "Critical",
                    "Malware signature matched in activity log from " + source + " / " + ip + ". " +
                    "Possible ransomware, rootkit or worm propagation in progress.",
                    "T1204 (User Execution) / T1486 (Data Encrypted for Impact)");
                createIoc("IP", ip, "Malware C2 / Source IP");
            }

            // ── RULE 15: C2 Communication ─────────────────────────────────
            if (payload.contains("185.220.101") || payload.contains("backdoor-c2")
                    || payload.contains(":4444") || payload.contains(":9001")
                    || payload.contains(":1337") || payload.contains("c2.") ) {
                createAlert("Command & Control Communication", "Critical",
                    "Outbound connection to known C2 indicator detected from " + source + " to " + ip + ". " +
                    "Active beaconing or data exfiltration channel suspected.",
                    "T1071 (Application Layer Protocol)");
                createIoc("IP", ip, "Active C2 Server IP");
            }

            // ── RULE 16: Data Exfiltration ────────────────────────────────
            if (action.contains("exfiltration") || payload.contains("exfiltration")
                    || payload.contains("data transfer") || payload.contains("sftp upload")
                    || payload.contains("uploaded") && payload.contains(".zip")) {
                createAlert("Data Exfiltration", "Critical",
                    "Unauthorized outbound data transfer detected. Sensitive archive uploaded to remote host " + ip + ".",
                    "T1048 (Exfiltration Over Alternative Protocol)");
                createIoc("Hash", "d940b54316d3f28f8045f28439401490214a3f2b4c107db580b06b2f4c10643b", "Exfiltrated Archive SHA-256");
            }
        }
    }

    private void extractAndCreateUrlIoc(String payload) {
        try {
            int idx = payload.indexOf("http");
            if (idx != -1) {
                String sub = payload.substring(idx);
                int end = sub.indexOf("'");
                if (end == -1) end = sub.indexOf("\"");
                if (end == -1) end = sub.indexOf(" ");
                if (end == -1) end = Math.min(100, sub.length());
                String url = sub.substring(0, end);
                createIoc("URL", url, "Malware Payload URL");
                String domain = url.replace("http://", "").replace("https://", "").split("/")[0];
                createIoc("Domain", domain, "Malware Delivery Domain");
            }
        } catch (Exception ignored) {}
    }

    private void createAlert(String type, String severity, String description, String mitre) {
        List<ThreatDetection> existing = detectionRepository.findAll();
        for (ThreatDetection current : existing) {
            if (current.getThreatType().equalsIgnoreCase(type)) return;
        }
        ThreatDetection detection = new ThreatDetection(null, type, severity, LocalDateTime.now(), description, mitre, "Active");
        detectionRepository.save(detection);
    }

    private void createIoc(String type, String value, String desc) {
        if (value == null || value.isBlank() || value.equals("unknown")) return;
        List<Ioc> existing = iocRepository.findAll();
        for (Ioc current : existing) {
            if (current.getValue().equalsIgnoreCase(value)) return;
        }
        Ioc ioc = new Ioc(null, type, value, desc, "System Detection Engine");
        iocRepository.save(ioc);
    }
}
