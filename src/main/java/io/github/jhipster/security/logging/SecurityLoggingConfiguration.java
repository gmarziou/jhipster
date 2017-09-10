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

import io.github.jhipster.config.JHipsterProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configures security logging.
 * <p>
 * It can be scanned or imported: <code>@Import(SecurityLoggingConfiguration.class)</code>
 */
@Configuration
@ConditionalOnProperty(prefix = "jhipster.logging.logstash.security-logging", name = "enabled", matchIfMissing = false)
public class SecurityLoggingConfiguration {

    private final String loggerName;

    public SecurityLoggingConfiguration(JHipsterProperties jHipsterProperties) {
        loggerName = jHipsterProperties.getLogging().getLogstash().getSecurityLogging().getLoggerName();
    }

    @Bean
    public UriAuthorizationAuditListener authorizationAuditListener() {
        return new UriAuthorizationAuditListener();
    }

    @Bean
    public SecurityAuditEventLogger securityEventLogger() {
        return new SecurityAuditEventLogger(loggerName);
    }

}
