/*
 * Copyright 2016-2017 the original author or authors from the JHipster project.
 *
 * This file is part of the JHipster project, see https://jhipster.github.io/
 * for more information.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.jhipster.security.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Map;

import static org.springframework.boot.actuate.security.AuthenticationAuditListener.AUTHENTICATION_FAILURE;
import static org.springframework.boot.actuate.security.AuthenticationAuditListener.AUTHENTICATION_SUCCESS;
import static org.springframework.boot.actuate.security.AuthorizationAuditListener.AUTHORIZATION_FAILURE;

/**
 * Component responsible for listening to security events and logging them.
 * Event data are stored in the MDC so that they can be used as raw fields in ELK rather than indexed from
 * text messages.
 */
@Component
public class SecurityAuditEventLogger {

    protected final Logger log;

    public static final String DATA_PRINCIPAL = "principal";
    public static final String DATA_TYPE = "type";
    public static final String DATA_MESSAGE = "message";
    public static final String DATA_ROLES = "roles";
    public static final String DATA_URI = "url";
    public static final String DATA_HTTP_METHOD = "method";

    public SecurityAuditEventLogger(String loggerName) {
        log = LoggerFactory.getLogger(loggerName);
    }

    /**
     * We store event into the MDC so that logstash appender can transmit them as JSON fields to ELK.
     */
    @EventListener
    public void onAuditEvent(AuditApplicationEvent event) {
        AuditEvent auditEvent = event.getAuditEvent();

        // Backup MDC
        Map<String, String> copy = MDC.getCopyOfContextMap();

        Map<String, Object> eventData = auditEvent.getData();

        String auditEventType = auditEvent.getType();
        MDC.put(DATA_TYPE, auditEventType);
        MDC.put(DATA_PRINCIPAL, auditEvent.getPrincipal());
        copyToMDC(eventData, DATA_ROLES);
        copyToMDC(eventData, DATA_URI);
        copyToMDC(eventData, DATA_HTTP_METHOD);

        logEvent(auditEvent, auditEventType, eventData);

        // Restore MDC
        if (copy != null) {
            MDC.setContextMap(copy);
        } else {
            MDC.clear();
        }
    }

    /**
     * Copy a value from event data map to MDC if value is set.
     */
    private void copyToMDC(Map<String, Object> eventData, String key) {
        if (eventData.get(key) != null) {
            MDC.put(key, (String) eventData.get(key));
        }
    }

    /**
     * Log the event with logging level and message dependeing on its type.
     */
    private void logEvent(AuditEvent auditEvent, String auditEventType, Map<String, Object> eventData) {
        switch (auditEventType) {
            case AUTHENTICATION_FAILURE:
                log.warn("{} for principal: '{}', message: {}",
                        auditEventType,
                        auditEvent.getPrincipal(),
                        eventData.get(DATA_MESSAGE)
                );
                break;

            case AUTHORIZATION_FAILURE:
                log.warn("{} for principal: '{}' with roles {}, message: {}",
                        auditEventType,
                        auditEvent.getPrincipal(),
                        eventData.get(DATA_ROLES),
                        eventData.get(DATA_MESSAGE)
                );
                break;

            case AUTHENTICATION_SUCCESS:
                log.info("{} for principal: '{}' with roles {}",
                        auditEventType,
                        auditEvent.getPrincipal(),
                        eventData.get(DATA_ROLES)
                );
                break;

            default:
                log.error("{} for principal: '{}', data: '{}'",
                        auditEventType,
                        auditEvent.getPrincipal(),
                        eventData
                );
        }
    }
}
