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

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.security.AbstractAuthorizationAuditListener;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import static io.github.jhipster.security.logging.SecurityAuditEventLogger.*;
import static org.springframework.boot.actuate.security.AuthenticationAuditListener.AUTHENTICATION_FAILURE;
import static org.springframework.boot.actuate.security.AuthorizationAuditListener.AUTHORIZATION_FAILURE;

/**
 * Component that listens to authorisation failure events, extracts information from them and pbulish them as AuditEvent.
 * <p>
 * It's a customizsation of AuthorizationAuditListener from spring-boot actuator in order to add the accessed URI
 * to the event data.
 */
@Component
public class UriAuthorizationAuditListener extends AbstractAuthorizationAuditListener {

    @Override
    public void onApplicationEvent(AbstractAuthorizationEvent event) {
        if (event instanceof AuthenticationCredentialsNotFoundEvent) {
            onAuthenticationCredentialsNotFoundEvent(
                    (AuthenticationCredentialsNotFoundEvent) event);
        } else if (event instanceof AuthorizationFailureEvent) {
            onAuthorizationFailureEvent((AuthorizationFailureEvent) event);
        }
    }

    private void onAuthenticationCredentialsNotFoundEvent(
            AuthenticationCredentialsNotFoundEvent event) {
        Map<String, Object> data = new HashMap<>();
        data.put(DATA_TYPE, event.getCredentialsNotFoundException().getClass().getName());
        data.put(DATA_MESSAGE, event.getCredentialsNotFoundException().getMessage());
        publish(new AuditEvent("<unknown>", AUTHENTICATION_FAILURE, data));
    }

    private void onAuthorizationFailureEvent(AuthorizationFailureEvent event) {
        Map<String, Object> data = new HashMap<>();
        data.put(DATA_TYPE, event.getAccessDeniedException().getClass().getName());
        data.put(DATA_MESSAGE, event.getAccessDeniedException().getMessage());
        Object source = event.getSource();
        if (source instanceof FilterInvocation) {
            FilterInvocation invocation = (FilterInvocation) source;
            data.put(DATA_URI, invocation.getRequest().getRequestURI());
            data.put(DATA_HTTP_METHOD, invocation.getHttpRequest().getMethod());
        }
        Authentication authentication = event.getAuthentication();
        String authorities = authentication.getAuthorities().toString();
        data.put(DATA_ROLES, authorities);
        publish(new AuditEvent(authentication.getName(), AUTHORIZATION_FAILURE, data));
    }

}
