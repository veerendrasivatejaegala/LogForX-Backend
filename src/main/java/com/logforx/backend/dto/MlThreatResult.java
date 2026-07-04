package com.logforx.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MlThreatResult {
    private String threatKey;
    private String threatType;
    private String severity;
    private double confidence;
    private String mitreTechnique;
    private String description;
    private String detectionSource;
}
