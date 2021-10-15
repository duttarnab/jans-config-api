package io.jans.configapi.plugin.casa.rest;

import io.jans.configapi.filters.ProtectedApi;
import io.jans.configapi.plugin.casa.service.OxdService;
import io.jans.configapi.service.auth.ConfigurationService;

import java.util.*;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.gluu.casa.conf.MainSettings;
import org.gluu.casa.conf.OxdClientSettings;
import org.gluu.casa.conf.OxdSettings;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.OK;

@ApplicationScoped
@Path("/oxd")
@ProtectedApi(scopes = BaseResource.CASA_CONFIG_SCOPE)
public class OxdResource extends BaseResource {

    private static final String DEFAULT_ACR = "casa";

    private static final List<String> REQUIRED_SCOPES = Arrays.asList("openid", "profile", "user_name", "clientinfo", "oxd");

    @Inject
    private ConfigurationService configurationService;

    private String issuer;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieve() {

        Response.Status httpStatus;
        String json = null;
        logger.debug("OxdConfWS retrieve operation called");

        try {
            OxdSettings oxdSettings = getCasaSettings().getOxdSettings();
            OxdClientSettings clientSettings = oxdSettings.getClient(); 
            oxdSettings.setClient(null);

            Map<String, Object> map = new LinkedHashMap<>();
            map.put("settings", oxdSettings);
            map.put("client_details", clientSettings);

            json = mapper.writeValueAsString(map);
            httpStatus = OK;
        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response replace(OxdSettings oxdSettings) {

        Response.Status httpStatus;
        String json = null;
        logger.debug("OxdConfWS replace operation called");

        try {
            MainSettings mainSettings = getCasaSettings();

            //Override host and acrs passed in
            oxdSettings.setOpHost(issuer);
            oxdSettings.setAcrValues(Collections.singletonList(DEFAULT_ACR));
            OxdService oxdService = new OxdService(oxdSettings);

            logger.info("Trying to override current OXD configuration with {}", mapper.writeValueAsString(oxdSettings));
            oxdService.updateOxdSettings(mainSettings.getOxdSettings().getClient().getOxdId());

            // oxdService mutates oxdSettings variable
            mainSettings.setOxdSettings(oxdSettings);
            saveSettings(mainSettings);
            json = mapper.writeValueAsString(mainSettings.getOxdSettings().getClient());
            httpStatus = OK;

        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @PostConstruct
    private void init() {
        issuer = configurationService.find().getIssuer();
    }

}
