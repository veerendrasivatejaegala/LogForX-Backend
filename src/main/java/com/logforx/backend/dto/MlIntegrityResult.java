package com.logforx.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MlIntegrityResult {
    private String prediction;
    private double passScore;
    private double failScore;
    private String source;
}
