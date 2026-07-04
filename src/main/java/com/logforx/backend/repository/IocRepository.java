package com.logforx.backend.repository;

import com.logforx.backend.model.Ioc;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IocRepository extends JpaRepository<Ioc, Long> {
}
