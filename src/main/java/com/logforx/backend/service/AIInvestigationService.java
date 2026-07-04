package com.logforx.backend.service;

import com.logforx.backend.model.ThreatDetection;
import com.logforx.backend.repository.ThreatDetectionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class AIInvestigationService {

    @Autowired
    private ThreatDetectionRepository detectionRepository;

    public Map<String, Object> getInvestigationCopilotData() {
        List<ThreatDetection> detections = detectionRepository.findAll();
        
        Map<String, Object> response = new HashMap<>();
        
        if (detections.isEmpty()) {
            response.put("incidentSummary", "No active security incidents flagged. Platform monitoring remains normal.");
            response.put("rootCause", "N/A - Clean environment status.");
            response.put("attackExplanation", "No adversarial progression models matched.");
            response.put("recommendations", List.of(
                "Maintain active log ingestion pipelines.",
                "Ensure periodic system audit logs review."
            ));
            return response;
        }
        
        boolean hasBruteForce = detections.stream().anyMatch(d -> d.getThreatType().toLowerCase().contains("brute"));
        boolean hasMalware = detections.stream().anyMatch(d -> d.getThreatType().toLowerCase().contains("malicious"));
        boolean hasC2 = detections.stream().anyMatch(d -> d.getThreatType().toLowerCase().contains("control"));
        boolean hasExfil = detections.stream().anyMatch(d -> d.getThreatType().toLowerCase().contains("exfiltration"));
        
        StringBuilder summary = new StringBuilder("AI Agent detected an active multi-stage attack lifecycle: ");
        List<String> tactics = detections.stream().map(ThreatDetection::getThreatType).collect(Collectors.toList());
        summary.append(String.join(" -> ", tactics)).append(".");
        
        String rootCause = "Initial intrusion achieved via remote credential guessing (Brute Force) targeting service port exposures (e.g. SSH/WinRM/Logon port).";
        
        StringBuilder explanation = new StringBuilder("Adversary started by performing a brute-force campaign against public-facing administrative accounts. ");
        if (hasBruteForce) {
            explanation.append("After compromising credentials, the threat actor authenticated successfully. ");
        }
        if (hasMalware) {
            explanation.append("The actor immediately spawned an obfuscated PowerShell child-process to download secondary malware binaries. ");
        }
        if (hasC2) {
            explanation.append("Following execution, a reverse TCP connection was established to remote C2 infrastructure (185.220.101.4), enabling shell access. ");
        }
        if (hasExfil) {
            explanation.append("Finally, sensitive files were packaged into C:\\ProgramData\\temp.zip and exfiltrated over alternative protocols.");
        }
        
        List<String> recommendations = List.of(
            "Enforce Multi-Factor Authentication (MFA) on all administrative interfaces immediately.",
            "Isolate compromised host 192.168.1.142 from the production network segment.",
            "Revoke compromised 'administrator' account credentials and review active directory memberships.",
            "Block outbound TCP connections to IP 185.220.101.4 and domain backdoor-c2.net on enterprise firewalls.",
            "Deploy endpoint detection rules to alert on obfuscated PowerShell execution formats (-nop -w hidden)."
        );
        
        response.put("incidentSummary", summary.toString());
        response.put("rootCause", rootCause);
        response.put("attackExplanation", explanation.toString());
        response.put("recommendations", recommendations);
        
        return response;
    }
}
