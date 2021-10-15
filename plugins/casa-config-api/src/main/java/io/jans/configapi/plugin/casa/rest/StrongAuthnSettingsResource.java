package io.jans.configapi.plugin.casa.rest;

import io.jans.configapi.filters.ProtectedApi;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.gluu.casa.conf.Basic2FASettings;
import org.gluu.casa.conf.MainSettings;
import org.gluu.casa.plugins.strongauthn.conf.Configuration;
import org.gluu.casa.plugins.strongauthn.conf.EnforcementPolicy;
import org.gluu.casa.plugins.strongauthn.conf.TrustedDevicesSettings;

import org.slf4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.NOT_FOUND;
import static javax.ws.rs.core.Response.Status.OK;

@Path("/pl/" + StrongAuthnSettingsResource.PLUGIN_ID + "/config")
@ProtectedApi(scopes = BaseResource.CASA_CONFIG_SCOPE)
public class StrongAuthnSettingsResource extends BaseResource {

    static final String PLUGIN_ID = "strong-authn-settings";

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieve() {

        Response.Status httpStatus;
        String json = null;

        logger.debug("StrongAuthnSettingsWS retrieve operation called");
        try {
            Configuration cfg = getPluginConfiguration(getCasaSettings(), PLUGIN_ID, Configuration.class);
            if (cfg == null) {
                httpStatus = NOT_FOUND;
            } else {
                json = mapper.writeValueAsString(cfg);
                httpStatus = OK;
            }
        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @POST
    @Path("basic")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public Response setBasicConfig(Basic2FASettings settings) {

        Response.Status httpStatus;
        String json = null;

        logger.debug("StrongAuthnSettingsWS setBasicConfig operation called");
        try {
            httpStatus = BAD_REQUEST;            
            if (settings == null) {
                json = "Empty payload";
                logger.warn(json);

            } else {
                if (settings.getMinCreds() < 1) {
                    json = "Minimum number of credentials expected to be greater than zero";
                    logger.warn(json);

                } else if (!settings.isAutoEnable() && !settings.isAllowSelfEnableDisable()) {
                    json = "Cannot prevent users to turn 2FA on/off when there is no 2FA auto-enablement";
                    logger.warn(json);

                } else {
                    MainSettings mainSettings = getCasaSettings();
                    Configuration cfg = getPluginConfiguration(mainSettings, PLUGIN_ID, Configuration.class);

                    cfg.setBasic2FASettings(settings);
                    setPluginConfiguration(mainSettings, PLUGIN_ID, cfg);
                    mainSettings.setBasic2FASettings(settings);
                    saveSettings(mainSettings);
                    httpStatus = OK;
                }
            }
        } catch (Exception e) {            
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @POST
    @Path("enforcement-policies")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public Response setEnforcementPolicies(List<EnforcementPolicy> policies) {

        Response.Status httpStatus;
        String json = null;

        logger.trace("StrongAuthnSettingsWS setEnforcementPolicies operation called");
        try {
            httpStatus = BAD_REQUEST;

            if (policies == null) {
                json = "Empty payload";
                logger.warn(json);

            } else if (policies.size() == 1 || (policies.size() == 2 && policies.contains(EnforcementPolicy.LOCATION_UNKNOWN)
                && policies.contains(EnforcementPolicy.DEVICE_UNKNOWN))) {

                MainSettings mainSettings = getCasaSettings();
                Configuration cfg = getPluginConfiguration(mainSettings, PLUGIN_ID, Configuration.class);

                cfg.setEnforcement2FA(policies);
                setPluginConfiguration(mainSettings, PLUGIN_ID, cfg);
                saveSettings(mainSettings);
                httpStatus = OK;
            } else {
                json = String.format("Unacceptable combination of policies %s", policies);
                logger.warn(json);

            }
        } catch (Exception e) {            
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @POST
    @Path("trusted-devices")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public Response setTrustedDevices(TrustedDevicesSettings settings) {

        Response.Status httpStatus;
        String json = null;

        logger.trace("StrongAuthnSettingsWS setTrustedDevices operation called");
        try {
            httpStatus = BAD_REQUEST;

            if (settings == null) {
                json = "Empty payload";
                logger.warn(json);

            } else {
                int lexp = Optional.ofNullable(settings.getLocationExpirationDays()).orElse(0);
                int dexp = Optional.ofNullable(settings.getDeviceExpirationDays()).orElse(0);

                if (lexp > 0 && dexp > 0) {
                    MainSettings mainSettings = getCasaSettings();
                    Configuration cfg = getPluginConfiguration(mainSettings, PLUGIN_ID, Configuration.class);

                    cfg.setTrustedDevicesSettings(settings);
                    setPluginConfiguration(mainSettings, PLUGIN_ID, cfg);
                    saveSettings(mainSettings);
                    httpStatus = OK;
                } else {
                    json = "One or more of the provided expiration values are invalid";
                    logger.warn(json);
                }
            }
        } catch (Exception e) {            
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

}
