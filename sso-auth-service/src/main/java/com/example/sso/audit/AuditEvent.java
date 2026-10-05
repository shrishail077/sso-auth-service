package com.example.sso.audit;

import java.time.Instant;

public record AuditEvent(String eventId, String type, String username, String detail, Instant timestamp) { }
