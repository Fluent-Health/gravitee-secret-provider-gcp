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
 * {@code ApiManager.register(...)}, and watches the directory. That is what makes a deployed-API test
 * affordable here: no MongoDB, no management API.
 *
 * <p><b>Only ENTRY_CREATE is usable for a V4 API.</b> The watcher's ENTRY_MODIFY and ENTRY_DELETE
 * branches both do {@code (io.gravitee.gateway.handlers.api.definition.Api) definitions.get(path)} —
 * the <em>V2</em> reactable class. For a V4 api that is a {@code ClassCastException} thrown inside the
 * {@code Flowable.interval} map function, which terminates the watcher for the rest of the process.
 * So a redeploy has to arrive as a <em>new file</em> naming the same api id with a higher
 * {@code deployment_number} and a later {@code createdAt}, and it has to arrive by a rename into the
 * directory rather than a write, or the trailing ENTRY_MODIFY kills the watcher anyway.
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
        return definition(new Revision(apiId, upstreamTarget, headerName, headerValue, "1", System.currentTimeMillis(), true));
    }

    /**
     * One deployable revision of an API.
     *
     * <p>{@code revision} and {@code createdAt} are what make a redeploy a redeploy.
     * {@code ApiMapper} reads the revision off the {@code deployment_number} event property and
     * {@code deployedAt} off the event's {@code createdAt}, and {@code ApiManagerImpl.doRegister}
     * treats an api as an <em>update</em> only when both moved — a later {@code deployedAt}
     * <em>and</em> a different revision. Get either wrong and the file is read, mapped, and then
     * silently ignored.
     *
     * @param started {@code false} maps to {@code lifecycleState} other than {@code STARTED}, which
     *     {@code ApiMapper} turns into {@code enabled=false}; {@code update()} then undeploys the api
     *     instead of updating it. That is the cheapest way to reach {@code undeploy}, because the
     *     obvious route — deleting the registry file — goes through
     *     {@code LocalApiSynchronizer}'s ENTRY_DELETE branch, which casts to the <em>V2</em> api class
     *     and throws {@code ClassCastException} for anything V4.
     * @param headerValue when {@code null} the flow carries no policy step at all, i.e. a revision
     *     that references no secret
     */
    record Revision(
        String apiId,
        String upstreamTarget,
        String headerName,
        String headerValue,
        String revision,
        long createdAt,
        boolean started
    ) {
        Revision at(String revision, long createdAt) {
            return new Revision(apiId, upstreamTarget, headerName, headerValue, revision, createdAt, started);
        }

        Revision stopped() {
            return new Revision(apiId, upstreamTarget, headerName, headerValue, revision, createdAt, false);
        }
    }

    static String definition(Revision spec) {
        String apiId = spec.apiId();
        String upstreamTarget = spec.upstreamTarget();
        String headerName = spec.headerName();
        String headerValue = spec.headerValue();

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
        if (headerValue != null) {
            ObjectNode step = flow.putArray("request").addObject();
            step.put("name", "add-credential-header");
            step.put("enabled", true);
            step.put("policy", "transform-headers");
            ObjectNode headers = step.putObject("configuration");
            ObjectNode header = headers.putArray("addHeaders").addObject();
            header.put("name", headerName);
            header.put("value", headerValue);
        }

        ObjectNode repositoryApi = MAPPER.createObjectNode();
        repositoryApi.put("id", apiId);
        repositoryApi.put("name", apiId);
        repositoryApi.put("definitionVersion", "4.0.0");
        repositoryApi.put("type", "proxy");
        repositoryApi.put("lifecycleState", spec.started() ? "STARTED" : "STOPPED");
        repositoryApi.put("environmentId", "DEFAULT");
        repositoryApi.put("definition", writeAsString(v4));

        ObjectNode event = MAPPER.createObjectNode();
        event.put("id", "evt-%s-%s".formatted(apiId, spec.revision()));
        event.put("type", "PUBLISH_API");
        event.put("payload", writeAsString(repositoryApi));
        event.put("createdAt", spec.createdAt());
        ObjectNode properties = event.putObject("properties");
        properties.put("api_id", apiId);
        properties.put("deployment_number", spec.revision());

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
