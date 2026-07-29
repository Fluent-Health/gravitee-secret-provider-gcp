/*
 * Copyright © 2026 Fluent Health (https://fluentinhealth.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.fluenthealth.gravitee.secretprovider.gcp.core;

import io.gravitee.secrets.api.plugin.SecretManagerConfiguration;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Configuration for the GCP secret provider, read from the {@code secrets.gcp.*} section of
 * {@code gravitee.yml} (or the equivalent {@code GRAVITEE_SECRETS_GCP_*} environment variables).
 *
 * <p>The single {@code Map<String, Object>} constructor is mandatory and is invoked reflectively by
 * {@code GraviteeConfigurationSecretResolver#readConfiguration}, using the plugin's own
 * classloader. It must therefore stay public with exactly that signature.
 */
public class GcpConfig implements SecretManagerConfiguration {

    /** Resolving {@code latest} rather than a pinned version is what makes rotation transparent. */
    public static final String LATEST_VERSION = "latest";

    public static final String DEFAULT_SECRET_MANAGER_BASE_URL = "https://secretmanager.googleapis.com";
    public static final String DEFAULT_METADATA_BASE_URL = "http://metadata.google.internal";

    private static final String CONFIG_PREFIX = "secrets.gcp.";

    private final boolean enabled;
    private final String projectId;
    private final String defaultVersion;
    private final int connectTimeoutMs;
    private final int requestTimeoutMs;
    private final String serviceAccountKeyFile;
    private final Duration secretTtl;
    private final String secretManagerBaseUrl;
    private final String metadataBaseUrl;

    public GcpConfig(Map<String, Object> conf) {
        Objects.requireNonNull(conf);
        this.enabled = booleanAt(conf, "enabled", false);
        if (!this.enabled) {
            // Mirrors the OSS Kubernetes provider: a disabled provider reads nothing, so an
            // otherwise incomplete `secrets.gcp` block must not break gateway startup.
            this.projectId = null;
            this.defaultVersion = LATEST_VERSION;
            this.connectTimeoutMs = 0;
            this.requestTimeoutMs = 0;
            this.serviceAccountKeyFile = "";
            this.secretTtl = Duration.ZERO;
            this.secretManagerBaseUrl = DEFAULT_SECRET_MANAGER_BASE_URL;
            this.metadataBaseUrl = DEFAULT_METADATA_BASE_URL;
            return;
        }
        this.projectId = required(conf, "projectId");
        this.defaultVersion = stringAt(conf, "defaultVersion", LATEST_VERSION);
        this.connectTimeoutMs = intAt(conf, "connectTimeoutMs", 3_000);
        this.requestTimeoutMs = intAt(conf, "requestTimeoutMs", 5_000);
        this.serviceAccountKeyFile = stringAt(conf, "serviceAccountKeyFile", "");
        this.secretTtl = Duration.ofSeconds(longAt(conf, "secretTtlSeconds", 300L));
        this.secretManagerBaseUrl = trimTrailingSlash(stringAt(conf, "baseUrl", DEFAULT_SECRET_MANAGER_BASE_URL));
        this.metadataBaseUrl = trimTrailingSlash(stringAt(conf, "metadataBaseUrl", DEFAULT_METADATA_BASE_URL));
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public String projectId() {
        return projectId;
    }

    /** Secret version used when the secret URL does not name one. */
    public String defaultVersion() {
        return defaultVersion;
    }

    public int connectTimeoutMs() {
        return connectTimeoutMs;
    }

    public int requestTimeoutMs() {
        return requestTimeoutMs;
    }

    public String serviceAccountKeyFile() {
        return serviceAccountKeyFile;
    }

    /**
     * How long a resolved secret stays valid. Surfaced as the {@code SecretMap} expiry, which is
     * what drives re-resolution — the EE secrets service renews on expiry, and in mode A2 our own
     * cache uses the same window. This is the upper bound on how long a rotation goes unnoticed.
     */
    public Duration secretTtl() {
        return secretTtl;
    }

    public String secretManagerBaseUrl() {
        return secretManagerBaseUrl;
    }

    public String metadataBaseUrl() {
        return metadataBaseUrl;
    }

    /**
     * True when credentials come from the GKE metadata server (Workload Identity), which is the
     * only supported production mode — no static key material. A configured
     * {@code serviceAccountKeyFile} is a local-development escape hatch.
     */
    public boolean usesMetadataServer() {
        return serviceAccountKeyFile == null || serviceAccountKeyFile.isBlank();
    }

    private static String required(Map<String, Object> conf, String key) {
        String value = stringAt(conf, key, "");
        if (value.isBlank()) {
            throw new IllegalArgumentException("'%s%s' is required when the GCP secret provider is enabled".formatted(CONFIG_PREFIX, key));
        }
        return value;
    }

    private static String stringAt(Map<String, Object> conf, String key, String defaultValue) {
        Object value = conf.get(key);
        return value == null ? defaultValue : String.valueOf(value).trim();
    }

    /*
     * These read Number as well as String rather than delegating to ConfigHelper#getProperty.
     * That helper matches the declared type exactly and otherwise only converts from String, so an
     * `int` property supplied as a YAML integer where a long is expected (or vice versa) throws.
     * Which of the two a value arrives as depends on whether it came from gravitee.yml or from an
     * environment variable, so neither can be assumed.
     */
    private static boolean booleanAt(Map<String, Object> conf, String key, boolean defaultValue) {
        Object value = conf.get(key);
        if (value == null) {
            return defaultValue;
        }
        return value instanceof Boolean bool ? bool : Boolean.parseBoolean(String.valueOf(value).trim());
    }

    private static int intAt(Map<String, Object> conf, String key, int defaultValue) {
        return Math.toIntExact(longAt(conf, key, defaultValue));
    }

    private static long longAt(Map<String, Object> conf, String key, long defaultValue) {
        Object value = conf.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(String.valueOf(value).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("'%s%s' must be a number, but was '%s'".formatted(CONFIG_PREFIX, key, value), e);
        }
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
