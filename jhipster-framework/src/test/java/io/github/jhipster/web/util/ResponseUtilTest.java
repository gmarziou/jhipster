/*
 * Copyright 2016-2019 the original author or authors from the JHipster project.
 *
 * This file is part of the JHipster project, see https://www.jhipster.tech/
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

package io.github.jhipster.web.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

public class ResponseUtilTest {

    private static final String HEADER_NAME = "X-Test";
    private static final String HEADER_VALUE = "FooBar";

    private Optional<Integer> yes;
    private Optional<Integer> no;
    private HttpHeaders headers;

    @BeforeEach
    public void setup() {
        yes = Optional.of(42);
        no = Optional.empty();
        headers = new HttpHeaders();
        headers.add(HEADER_NAME, HEADER_VALUE);
    }

    @Test
    public void testYesWithoutHeaders() {
        ResponseEntity<Integer> response = ResponseUtil.wrapOrNotFound(yes);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(42);
        assertThat(response.getHeaders()).isEmpty();
    }

    @Test
    public void testNoWithoutHeaders() {
        assertThatExceptionOfType(ResponseStatusException.class).isThrownBy(() -> ResponseUtil.wrapOrNotFound(no));
    }

    @Test
    public void testYesWithHeaders() {
        ResponseEntity<Integer> response = ResponseUtil.wrapOrNotFound(yes, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(42);
        assertThat(response.getHeaders()).hasSize(1);
        assertThat(response.getHeaders().get(HEADER_NAME)).hasSize(1);
        assertThat(response.getHeaders().get(HEADER_NAME).get(0)).isEqualTo(HEADER_VALUE);
    }

    @Test
    public void testNoWithHeaders() {
        assertThatExceptionOfType(ResponseStatusException.class).isThrownBy(() -> ResponseUtil.wrapOrNotFound(no, headers));
    }
}
