package io.jans.configapi.plugin.casa.service;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jans.ca.common.params.GetClientTokenParams;
import io.jans.ca.common.params.IParams;
import io.jans.ca.common.params.RegisterSiteParams;
import io.jans.ca.common.params.RemoveSiteParams;
import io.jans.ca.common.response.GetClientTokenResponse;
import io.jans.ca.common.response.RegisterSiteResponse;
import io.jans.ca.common.response.RemoveSiteResponse;

import java.util.Collections;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.gluu.casa.conf.OxdSettings;
import org.gluu.casa.conf.OxdClientSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OxdService {

    private ObjectMapper mapper;
    private Client client;
    private OxdSettings config;
    private Logger logger;

    public OxdService(OxdSettings config) {
        this.config = config;
        logger = LoggerFactory.getLogger(getClass());
        mapper =  new ObjectMapper();
        //client = builder.httpEngine(ClientFactory.instance().createEngine()).build();
        client = ClientBuilder.newClient();
    }

    public void updateOxdSettings(String oldOxdId) throws Exception {        
        config.setClient(doRegister());
        removeSite(oldOxdId);
    }

    private OxdClientSettings doRegister() throws Exception {

        OxdClientSettings computedSettings;
        String clientName;
        logger.info("Setting oxd configs (protocol:{}, host: {}, port: {}, post logout: {})",
                config.getProtocol(), config.getHost(), config.getPort(),  config.getPostLogoutUri());

        try {
            String timeStamp = Long.toString(System.currentTimeMillis()/1000);
            clientName = "gluu-casa_" + timeStamp;

            RegisterSiteParams cmdParams = new RegisterSiteParams();
            cmdParams.setOpHost(config.getOpHost());
            cmdParams.setRedirectUris(Collections.singletonList(config.getRedirectUri()));
            cmdParams.setPostLogoutRedirectUris(Collections.singletonList(config.getPostLogoutUri()));
            cmdParams.setAcrValues(config.getAcrValues());
            cmdParams.setClientName(clientName);
            cmdParams.setClientFrontchannelLogoutUri(config.getFrontLogoutUri());
            cmdParams.setGrantTypes(Collections.singletonList("client_credentials"));

            cmdParams.setScope(config.getScopes());
            cmdParams.setResponseTypes(Collections.singletonList("code"));

            RegisterSiteResponse setup = restResponse(cmdParams, "register-site", null, RegisterSiteResponse.class);
            computedSettings = new OxdClientSettings(clientName, setup.getRpId(), setup.getClientId(), setup.getClientSecret());

            logger.info("oxd client registered successfully, oxd-id={}", computedSettings.getOxdId());
        } catch (Exception e) {
            String msg = "Setting oxd-server configs failed";
            logger.error(msg, e);
            throw new Exception(msg, e);
        }
        return computedSettings;

    }

    private void removeSite(String oxdId) {

        try {
            RemoveSiteParams cmdParams = new RemoveSiteParams(oxdId);
            RemoveSiteResponse resp = restResponse(cmdParams, "remove-site", getPAT(), RemoveSiteResponse.class);
            logger.info("Site removed {}", resp.getRpId());
        } catch (Exception e) {
            logger.debug(e.getMessage(), e);
        }

    }

    private String getPAT() throws Exception {

        GetClientTokenParams cmdParams = new GetClientTokenParams();
        cmdParams.setOpHost(config.getOpHost());
        cmdParams.setClientId(config.getClient().getClientId());
        cmdParams.setClientSecret(config.getClient().getClientSecret());
        cmdParams.setScope(config.getScopes());

        GetClientTokenResponse resp = restResponse(cmdParams, "get-client-token", null, GetClientTokenResponse.class);
        String token = resp.getAccessToken();
        logger.trace("getPAT. token={}", token);

        return token;

    }

    private <T> T restResponse(IParams params, String path, String token, Class<T> responseClass) throws Exception {

        String payload = mapper.writeValueAsString(params);
        logger.trace("Sending /{} request to oxd-server with payload \n{}", path, payload);

        String authz = StringUtils.isEmpty(token) ? null : "Bearer " + token;
        WebTarget target = client.target(
            String.format("%s://%s:%s/%s", config.getProtocol(), config.getHost(), config.getPort(), path));

        Response response = target.request().header("Authorization", authz).post(Entity.json(payload));
        response.bufferEntity();
        logger.trace("Response received was \n{}", response.readEntity(String.class));
        return response.readEntity(responseClass);

    }

}
