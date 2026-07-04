package com.logforx.backend.repository;

import com.logforx.backend.model.Investigator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface InvestigatorRepository extends JpaRepository<Investigator, Long> {
    Optional<Investigator> findByEmail(String email);
    Optional<Investigator> findByBadgeId(String badgeId);
    boolean existsByEmail(String email);
    boolean existsByBadgeId(String badgeId);
}
