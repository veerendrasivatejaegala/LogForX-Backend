package com.logforx.backend.repository;

import com.logforx.backend.model.ForensicEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ForensicEventRepository extends JpaRepository<ForensicEvent, Long> {
    List<ForensicEvent> findAllByOrderByTimestampAsc();
}
