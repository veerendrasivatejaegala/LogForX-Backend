package com.logforx.backend.service;

import com.logforx.backend.model.ThreatDetection;
import com.logforx.backend.repository.ThreatDetectionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class RiskScoreService {

    @Autowired
    private ThreatDetectionRepository detectionRepository;

    public Map<String, Object> calculateRiskScore() {
        List<ThreatDetection> detections = detectionRepository.findAll();
        
        int score = 12; // Base risk score
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        
        for (ThreatDetection det : detections) {
            String sev = det.getSeverity().toLowerCase();
            if (sev.equals("critical")) {
                score += 35;
                criticalCount++;
            } else if (sev.equals("high")) {
                score += 20;
                highCount++;
            } else if (sev.equals("medium")) {
                score += 10;
                mediumCount++;
            } else {
                score += 3;
                lowCount++;
            }
        }
        
        if (score > 100) {
            score = 98; // Cap at 98
        }
        if (detections.isEmpty()) {
            score = 12;
        }
        
        String level = "Low";
        if (score >= 75) level = "Critical";
        else if (score >= 50) level = "High";
        else if (score >= 25) level = "Medium";
        
        Map<String, Object> result = new HashMap<>();
        result.put("score", score);
        result.put("level", level);
        result.put("criticalCount", criticalCount);
        result.put("highCount", highCount);
        result.put("mediumCount", mediumCount);
        result.put("lowCount", lowCount);
        
        return result;
    }
}
