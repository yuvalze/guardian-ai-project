package com.guardian.ai.repository;

import com.guardian.ai.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    List<SecurityEvent> findBySourceIp(String sourceIp);

    List<SecurityEvent> findByEventType(String eventType);

    List<SecurityEvent> findBySeverity(String severity);

    List<SecurityEvent> findByStatus(String status);

    List<SecurityEvent> findByTimestampBetween(LocalDateTime start, LocalDateTime end);

    @Query("SELECT se FROM SecurityEvent se WHERE se.sourceIp = :sourceIp AND se.eventType = :eventType ORDER BY se.timestamp DESC")
    List<SecurityEvent> findBySourceIpAndEventTypeOrderByTimestampDesc(@Param("sourceIp") String sourceIp, @Param("eventType") String eventType);

    @Query("SELECT COUNT(se) FROM SecurityEvent se WHERE se.sourceIp = :sourceIp AND se.timestamp >= :since")
    Long countBySourceIpSince(@Param("sourceIp") String sourceIp, @Param("since") LocalDateTime since);

    Optional<SecurityEvent> findTopBySourceIpOrderByTimestampDesc(String sourceIp);
}
