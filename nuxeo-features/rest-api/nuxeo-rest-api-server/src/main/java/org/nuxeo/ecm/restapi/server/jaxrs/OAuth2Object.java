/*
 * (C) Copyright 2016 Nuxeo (http://nuxeo.com/) and others.
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
 *
 * Contributors:
 *     Gabriel Barata <gbarata@nuxeo.com>
 */
package org.nuxeo.ecm.restapi.server.jaxrs;

import com.google.api.client.auth.oauth2.Credential;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.StatusType;

import org.nuxeo.ecm.automation.server.jaxrs.RestOperationException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.NuxeoException;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.platform.oauth2.providers.AbstractOAuth2UserEmailProvider;
import org.nuxeo.ecm.platform.oauth2.providers.NuxeoOAuth2ServiceProvider;
import org.nuxeo.ecm.platform.oauth2.providers.OAuth2ServiceProvider;
import org.nuxeo.ecm.platform.oauth2.providers.OAuth2ServiceProviderRegistry;
import org.nuxeo.ecm.platform.oauth2.tokens.NuxeoOAuth2Token;
import org.nuxeo.ecm.webengine.model.WebObject;
import org.nuxeo.ecm.webengine.model.impl.AbstractResource;
import org.nuxeo.ecm.webengine.model.impl.ResourceTypeImpl;
import org.nuxeo.runtime.api.Framework;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Endpoint to retrieve OAuth2 authentication data
 * @since 8.4
 */
@WebObject(type = "oauth2")
public class OAuth2Object extends AbstractResource<ResourceTypeImpl> {

    private static final String APPLICATION_JSON_NXENTITY = "application/json+nxentity";

    /**
     * Lists all oauth2 service providers.
     *
     * @since 9.1
     */
    @GET
    @Path("provider")
    public List<NuxeoOAuth2ServiceProvider> getProviders(@Context HttpServletRequest request) throws IOException, RestOperationException {
        return getProviders();
    }

    /**
     * Retrieves oauth2 data for a given provider.
     */
    @GET
    @Path("provider/{providerId}")
    public Response getProvider(@PathParam("providerId") String providerId,
                                @Context HttpServletRequest request) throws IOException, RestOperationException {
        return Response.ok(getProvider(providerId)).build();
    }

    /**
     * Creates a new OAuth2 service provider.
     *
     * @since 9.1
     */
    @POST
    @Path("provider")
    @Consumes({ APPLICATION_JSON_NXENTITY, "application/json" })
    public Response addProvider(@Context HttpServletRequest request, NuxeoOAuth2ServiceProvider provider)
        throws IOException, RestOperationException {
        if (!((NuxeoPrincipal)getContext().getCoreSession().getPrincipal()).isAdministrator()) {
            return Response.status(Status.FORBIDDEN).build();
        }
        Framework.doPrivileged(() -> {
            OAuth2ServiceProviderRegistry registry = Framework.getService(OAuth2ServiceProviderRegistry.class);
            registry.addProvider(provider.getServiceName(),
                provider.getDescription(),
                provider.getTokenServerURL(),
                provider.getAuthorizationServerURL(),
                provider.getUserAuthorizationURL(),
                provider.getClientId(),
                provider.getClientSecret(),
                provider.getScopes(),
                provider.isEnabled());
        });
        return Response.ok(getProvider(provider.getServiceName())).build();
    }

    /**
     * Updates an OAuth2 service provider.
     *
     * @since 9.1
     */
    @PUT
    @Path("provider/{providerId}")
    @Consumes({ APPLICATION_JSON_NXENTITY, "application/json" })
    public Response updateProvider(@PathParam("providerId") String providerId,
                                   @Context HttpServletRequest request, NuxeoOAuth2ServiceProvider provider)
        throws IOException, RestOperationException {
        if (!((NuxeoPrincipal)getContext().getCoreSession().getPrincipal()).isAdministrator()) {
            return Response.status(Status.FORBIDDEN).build();
        }
        getProvider(providerId);
        Framework.doPrivileged(() -> {
            OAuth2ServiceProviderRegistry registry = Framework.getService(OAuth2ServiceProviderRegistry.class);
            registry.updateProvider(providerId, provider);
        });
        return Response.ok(getProvider(provider.getServiceName())).build();
    }

    /**
     * Deletes an OAuth2 service provider.
     *
     * @since 9.1
     */
    @DELETE
    @Path("provider/{providerId}")
    public Response deleteProvider(@PathParam("providerId") String providerId, @Context HttpServletRequest request)
        throws IOException, RestOperationException {
        if (!((NuxeoPrincipal)getContext().getCoreSession().getPrincipal()).isAdministrator()) {
            return Response.status(Status.FORBIDDEN).build();
        }
        getProvider(providerId);
        Framework.doPrivileged(() -> {
            OAuth2ServiceProviderRegistry registry = Framework.getService(OAuth2ServiceProviderRegistry.class);
            registry.deleteProvider(providerId);
        });
        return Response.noContent().build();
    }

    /**
     * Retrieves a valid access token for a given provider and the current user.
     * If expired, the token will be refreshed.
     */
    @GET
    @Path("provider/{providerId}/token")
    public Response getToken(@PathParam("providerId") String providerId,
                             @Context HttpServletRequest request) throws IOException, RestOperationException {

        NuxeoOAuth2ServiceProvider provider = getProvider(providerId);

        String username = request.getUserPrincipal().getName();
        NuxeoOAuth2Token token = getToken(provider, username);
        if (token == null) {
            return Response.status(Status.NOT_FOUND).build();
        }
        Credential credential = getCredential(provider, token);

        if (credential == null) {
            return Response.status(Status.NOT_FOUND).build();
        }
        Long expiresInSeconds = credential.getExpiresInSeconds();
        if (expiresInSeconds != null && expiresInSeconds <= 0) {
            credential.refreshToken();
        }
        Map<String,Object> result = new HashMap<>();
        result.put("token", credential.getAccessToken());
        // TODO: make marshallers for Credentials and use Response.ok(result).build() instead
        return buildResponse(Status.OK, result);
    }

    private List<NuxeoOAuth2ServiceProvider> getProviders() {
        OAuth2ServiceProviderRegistry registry = Framework.getService(OAuth2ServiceProviderRegistry.class);
        return registry.getProviders().stream()
            .filter(provider -> provider instanceof NuxeoOAuth2ServiceProvider)
            .map(provider -> (NuxeoOAuth2ServiceProvider)provider)
            .collect(Collectors.toList());
    }

    private List<NuxeoOAuth2Token> getTokens(String nxuser) {
        // TODO: maybe avoid using the getProviders and access the directories instead
        return getProviders().stream().map(provider -> getToken(provider, nxuser)).collect(Collectors.toList());
    }

    private NuxeoOAuth2Token getToken(NuxeoOAuth2ServiceProvider provider, String nxuser) {
        Map<String, Serializable> filter = new HashMap<>();
        filter.put("serviceName", provider.getId());
        filter.put(NuxeoOAuth2Token.KEY_NUXEO_LOGIN, nxuser);
        return Framework.doPrivileged(() -> {
            List<DocumentModel> entries = provider.getCredentialDataStore().query(filter);
            if (entries != null) {
                if (entries.size() > 1) {
                    throw new NuxeoException("Found multiple " + provider.getId() + " accounts for " + nxuser);
                } else if (entries.size() == 1) {
                    return new NuxeoOAuth2Token(entries.get(0));
                }
            }
            return null;
        });
    }

    private Credential getCredential(NuxeoOAuth2ServiceProvider provider, NuxeoOAuth2Token token) {
        return provider.loadCredential(
            (provider instanceof AbstractOAuth2UserEmailProvider) ? token.getServiceLogin() : token.getNuxeoLogin());
    }

    private NuxeoOAuth2ServiceProvider getProvider(String providerId) throws RestOperationException {
        OAuth2ServiceProvider provider = Framework.getService(OAuth2ServiceProviderRegistry.class)
            .getProvider(providerId);
        if (provider == null || !(provider instanceof NuxeoOAuth2ServiceProvider)) {
            RestOperationException err = new RestOperationException("Invalid provider: " + providerId);
            err.setStatus(HttpServletResponse.SC_NOT_FOUND);
            throw err;
        }
        return (NuxeoOAuth2ServiceProvider) provider;
    }

    private Response buildResponse(StatusType status, Object obj) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        String message = mapper.writeValueAsString(obj);

        return Response.status(status)
            .header("Content-Length", message.getBytes("UTF-8").length)
            .type(MediaType.APPLICATION_JSON + "; charset=UTF-8")
            .entity(message)
            .build();
    }

    private Map<String,Object> parseResponse(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        TypeReference<HashMap<String,Object>> typeRef = new TypeReference<HashMap<String,Object>>() {};
        return mapper.readValue(json, typeRef);
    }

}
