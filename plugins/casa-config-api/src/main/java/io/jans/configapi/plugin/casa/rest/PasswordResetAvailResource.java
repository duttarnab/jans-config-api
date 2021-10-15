package io.jans.configapi.plugin.casa.rest;

import io.jans.configapi.filters.ProtectedApi;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.gluu.casa.conf.MainSettings;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.OK;

@ApplicationScoped
@Path("/pwd-reset")
@ProtectedApi( scopes = BaseResource.CASA_CONFIG_SCOPE )
public class PasswordResetAvailResource extends BaseResource {

    @GET
    @Path("available")
    @Produces(MediaType.APPLICATION_JSON)
    public Response available() {

        Response.Status httpStatus;
        String json;

        logger.debug("PasswordResetAvailWS available operation called");
        try {
            json = Boolean.toString(isPwdResetAvailable());
            httpStatus = OK;
        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @GET
    @Path("enabled")
    @Produces(MediaType.APPLICATION_JSON)
    public Response isEnabled() {

        Response.Status httpStatus;
        String json;

        logger.debug("PasswordResetAvailWS isEnabled operation called");
        try {
            json = Boolean.toString(isPwdResetAvailable() && getCasaSettings().isEnablePassReset());
            httpStatus = OK;
        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

    @POST
    @Path("turn-on")
    @Produces(MediaType.TEXT_PLAIN)
    public Response enable() {
        logger.debug("PasswordResetAvailWS enable operation called");
        return turnOnOff(true);
    }

    @POST
    @Path("turn-off")
    @Produces(MediaType.TEXT_PLAIN)
    public Response disable() {
        logger.debug("PasswordResetAvailWS disable operation called");
        return turnOnOff(false);
    }

    private Response turnOnOff(boolean flag) {

        Response.Status httpStatus;
        String json = null;

        try {
            MainSettings mainSettings = getCasaSettings();
            boolean value = mainSettings.isEnablePassReset();

            if (isPwdResetAvailable()) {
                if (value != flag) {
                    mainSettings.setEnablePassReset(flag);
                    logger.debug("Persisting configuration change");
                    saveSettings(mainSettings);
                }
                httpStatus = OK;
            } else {
                httpStatus = BAD_REQUEST;
                json = "Password reset is not available. Your server may be using an external " +
                    "LDAP for identities synchronization"; 
            }
        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();  

    }

    private boolean isPwdResetAvailable() {
        //TODO: there is no clarity on how to implement this for Gluu 5.0
        return true;
    }

}
