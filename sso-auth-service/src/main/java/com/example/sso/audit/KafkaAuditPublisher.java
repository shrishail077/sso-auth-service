package com.example.sso.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

/** Publishes audit events to Kafka. Keyed by username so one user's events stay ordered. */
@Component
@Profile("kafka")
public class KafkaAuditPublisher implements AuditPublisher {

    private static final Logger log = LoggerFactory.getLogger(KafkaAuditPublisher.class);

    private final KafkaTemplate<String, String> kafka;
    private final ObjectMapper mapper;
    private final String topic;

    public KafkaAuditPublisher(KafkaTemplate<String, String> kafka, ObjectMapper mapper,
                               @Value("${app.audit.topic}") String topic) {
        this.kafka = kafka;
        this.mapper = mapper;
        this.topic = topic;
    }

    @Override
    public void publish(AuditEvent event) {
        try {
            kafka.send(topic, event.username(), mapper.writeValueAsString(event));
        } catch (JsonProcessingException e) {
            log.warn("Could not serialize audit event {}", event.eventId(), e);
        }
    }
}
