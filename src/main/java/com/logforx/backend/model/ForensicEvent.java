package com.logforx.backend.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ForensicEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private LocalDateTime timestamp;
    private String eventType; // Login, Process, Network, FileSystem
    private String severity; // Low, Medium, High, Critical
    private String source;
    private String username;
    private String ipAddress;
    private String action;
    
    @Column(length = 2000)
    private String payloadDetails;
    
    private String evidenceFileName;
}
