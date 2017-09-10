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

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.FilterInvocation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static io.github.jhipster.security.logging.SecurityAuditEventLogger.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.boot.actuate.security.AuthorizationAuditListener.AUTHORIZATION_FAILURE;

/**
 * Tests UrlAuthorizationAuditListener class.
 */
public class UriAuthorizationAuditListenerTest {

    private UriAuthorizationAuditListener listener = new UriAuthorizationAuditListener();

    private final ApplicationEventPublisher publisher = mock(
        ApplicationEventPublisher.class);

    @Before
    public void init() {
        this.listener.setApplicationEventPublisher(this.publisher);
    }

    @Test
    public void onApplicationEvent() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        FilterInvocation source = new FilterInvocation(request, response, chain);

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        Authentication authentication = new UsernamePasswordAuthenticationToken("test", "", authorities);
        AccessDeniedException accessDeniedException = new AccessDeniedException("Access denied");
        Collection<ConfigAttribute> attributes = new ArrayList<>();

        AuthorizationFailureEvent failureEvent = new AuthorizationFailureEvent(source, attributes, authentication, accessDeniedException);
        AuditApplicationEvent event = handleAuthorizationEvent(failureEvent);

        AuditEvent auditEvent = event.getAuditEvent();
        assertThat(auditEvent.getType()).isEqualTo(AUTHORIZATION_FAILURE);
        assertThat(auditEvent.getPrincipal()).isEqualTo("test");

        Map<String, Object> eventData = auditEvent.getData();
        assertThat(eventData).containsEntry(DATA_HTTP_METHOD, "GET");
        assertThat(eventData).containsEntry(DATA_URI, "/api/test");
        assertThat(eventData).containsEntry(DATA_MESSAGE, "Access denied");
        assertThat(eventData).containsEntry(DATA_ROLES, "[ROLE_USER, ROLE_ADMIN]");
    }

    private AuditApplicationEvent handleAuthorizationEvent(AbstractAuthorizationEvent event) {
        ArgumentCaptor<AuditApplicationEvent> eventCaptor = ArgumentCaptor
            .forClass(AuditApplicationEvent.class);
        this.listener.onApplicationEvent(event);
        verify(this.publisher).publishEvent(eventCaptor.capture());
        return eventCaptor.getValue();
    }
}
