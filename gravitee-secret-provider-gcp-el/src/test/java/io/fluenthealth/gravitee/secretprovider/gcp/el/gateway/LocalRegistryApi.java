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
package io.fluenthealth.gravitee.secretprovider.gcp.el.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Builds a V4 API definition in the shape APIM's <em>local registry</em> expects.
 *
 * <p>Enabled with {@code services.sync.local.enabled: true} and {@code services.sync.local.path},
 * {@code LocalApiSynchronizer} reads every {@code *.json} in that directory, deploys it through
 * {@code ApiManager.register(...)}, and watches the directory so a rewritten file redeploys. That is
 * what makes a deployed-API test affordable here: no MongoDB, no management API.
 *
 * <p>The format is three levels of nesting, two of them JSON <em>strings</em>, which is why this is
 * built with Jackson rather than written by hand:
 *
 * <pre>
 * { "apiEvent": { "payload": "&lt;repository Api JSON&gt;" } }
 *                              └─ { "definition": "&lt;v4 Api definition JSON&gt;" }
 * </pre>
 *
 * <p><b>Enum values are LABELS, not enum names.</b> {@code DefinitionVersion}, {@code ApiType},
 * {@code ListenerType}, {@code SelectorType}, {@code PlanStatus} and {@code PlanMode} all
 * deserialise through {@code @JsonCreator valueOfLabel} or {@code @JsonValue}, so it is
 * {@code "4.0.0"} not {@code "V4"}, and {@code "proxy"} not {@code "PROXY"}. Getting
 * {@code definitionVersion} wrong is the nastiest of these: it silently routes the definition to the
 * <em>V2</em> deserializer, which then fails with "A proxy property is required" — an error that
 * says nothing about the real cause. {@code Operator} is the exception and uses plain names.
 *
 * <p>{@code ApiMapper.to(Event)} reads {@code payload} as a repository {@code Api}, switches on its
 * {@code definitionVersion}/{@code type} to pick the model, then parses {@code definition}. It also
 * sets {@code enabled} from {@code lifecycleState == STARTED}, and {@code ApiManagerImpl.deploy}
 * refuses an API with no published plan — hence both are set below.
 */
final class LocalRegistryApi {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LocalRegistryApi() {}

    /**
     * @param apiId the API id, also its context-path segment
     * @param upstreamTarget where the endpoint proxies to
     * @param headerName header the request policy adds
     * @param headerValue value for that header — a {@code secret://gcp/...} reference in these tests
     */
    static String definition(String apiId, String upstreamTarget, String headerName, String headerValue) {
        ObjectNode v4 = MAPPER.createObjectNode();
        v4.put("id", apiId);
        v4.put("name", apiId);
        v4.put("apiVersion", "1.0.0");
        v4.put("definitionVersion", "4.0.0");
        v4.put("type", "proxy");

        ObjectNode listener = v4.putArray("listeners").addObject();
        listener.put("type", "http");
        listener.putArray("paths").addObject().put("path", "/" + apiId);
        listener.putArray("entrypoints").addObject().put("type", "http-proxy");

        ObjectNode group = v4.putArray("endpointGroups").addObject();
        group.put("name", "default-group");
        group.put("type", "http-proxy");
        ObjectNode endpoint = group.putArray("endpoints").addObject();
        endpoint.put("name", "default");
        endpoint.put("type", "http-proxy");
        endpoint.put("inheritConfiguration", false);
        endpoint.putObject("configuration").put("target", upstreamTarget);

        ObjectNode plan = v4.putArray("plans").addObject();
        plan.put("id", "free-plan");
        plan.put("name", "free-plan");
        plan.put("status", "published");
        plan.put("mode", "standard");
        plan.putObject("security").put("type", "key-less");

        ObjectNode flow = v4.putArray("flows").addObject();
        flow.put("name", "inject-header");
        flow.put("enabled", true);
        ObjectNode selector = flow.putArray("selectors").addObject();
        selector.put("type", "http");
        selector.put("path", "/");
        selector.put("pathOperator", "STARTS_WITH");

        /*
         * transform-headers is chosen only because WireMock can observe the result. The mechanism is
         * field-agnostic: substitution rewrites the step's whole configuration JSON before the policy
         * deserialises it, so a field no EL can reach behaves identically.
         */
        ObjectNode step = flow.putArray("request").addObject();
        step.put("name", "add-credential-header");
        step.put("enabled", true);
        step.put("policy", "transform-headers");
        ObjectNode headers = step.putObject("configuration");
        ObjectNode header = headers.putArray("addHeaders").addObject();
        header.put("name", headerName);
        header.put("value", headerValue);

        ObjectNode repositoryApi = MAPPER.createObjectNode();
        repositoryApi.put("id", apiId);
        repositoryApi.put("name", apiId);
        repositoryApi.put("definitionVersion", "4.0.0");
        repositoryApi.put("type", "proxy");
        repositoryApi.put("lifecycleState", "STARTED");
        repositoryApi.put("environmentId", "DEFAULT");
        repositoryApi.put("definition", writeAsString(v4));

        ObjectNode event = MAPPER.createObjectNode();
        event.put("id", "evt-" + apiId);
        event.put("type", "PUBLISH_API");
        event.put("payload", writeAsString(repositoryApi));
        event.put("createdAt", System.currentTimeMillis());
        ObjectNode properties = event.putObject("properties");
        properties.put("api_id", apiId);
        properties.put("deployment_number", "1");

        ObjectNode file = MAPPER.createObjectNode();
        file.set("apiEvent", event);
        file.set("subscriptions", MAPPER.createArrayNode());
        file.set("apiKeys", MAPPER.createArrayNode());
        return writeAsString(file);
    }

    private static String writeAsString(ObjectNode node) {
        try {
            return MAPPER.writeValueAsString(node);
        } catch (Exception e) {
            throw new IllegalStateException("Could not serialise the local-registry definition", e);
        }
    }
}
