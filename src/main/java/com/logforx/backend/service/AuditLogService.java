package com.logforx.backend.service;

import com.logforx.backend.model.AuditLog;
import com.logforx.backend.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    public void logAction(String action, String investigatorId, String details) {
        AuditLog auditLog = new AuditLog(null, action, LocalDateTime.now(), investigatorId, details);
        auditLogRepository.save(auditLog);
    }

    public List<AuditLog> getAuditLogs() {
        return auditLogRepository.findAllByOrderByTimestampDesc();
    }
}
