package com.example.sso.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Default publisher (no Kafka needed). Active unless the 'kafka' profile is on. */
@Component
@Profile("!kafka")
public class LoggingAuditPublisher implements AuditPublisher {

    private static final Logger log = LoggerFactory.getLogger(LoggingAuditPublisher.class);

    @Override
    public void publish(AuditEvent event) {
        log.info("AUDIT {} user={} detail={}", event.type(), event.username(), event.detail());
    }
}
