package com.example.sso.audit;

import java.time.Instant;
import java.util.UUID;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private final AuditPublisher publisher;

    public AuditService(AuditPublisher publisher) {
        this.publisher = publisher;
    }

    /** Runs on the audit thread pool, so the caller (login path) is never blocked by Kafka latency. */
    @Async("auditExecutor")
    public void record(String type, String username, String detail) {
        publisher.publish(new AuditEvent(UUID.randomUUID().toString(), type, username, detail, Instant.now()));
    }
}
