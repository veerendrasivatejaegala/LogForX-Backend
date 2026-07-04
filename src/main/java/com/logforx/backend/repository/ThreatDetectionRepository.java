package com.logforx.backend.repository;

import com.logforx.backend.model.ThreatDetection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatDetectionRepository extends JpaRepository<ThreatDetection, Long> {
}
