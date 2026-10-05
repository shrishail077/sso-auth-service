package com.example.sso.audit;

public interface AuditPublisher {
    void publish(AuditEvent event);
}
