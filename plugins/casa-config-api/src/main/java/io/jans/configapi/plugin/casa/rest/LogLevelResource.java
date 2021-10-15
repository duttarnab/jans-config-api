package io.jans.configapi.plugin.casa.rest;

import io.jans.configapi.filters.ProtectedApi;

import java.util.Arrays;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.gluu.casa.conf.MainSettings;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.OK;

@ApplicationScoped
@Path("/log-level")
@ProtectedApi(scopes = BaseResource.CASA_CONFIG_SCOPE)
public class LogLevelResource extends BaseResource {

    private static final List<String> SLF4J_LEVELS = Arrays.asList("ERROR", "WARN", "INFO", "DEBUG", "TRACE");

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response get() {
        return Response.status(OK).entity(getCasaSettings().getLogLevel()).build();
    }

    @POST
    @Produces(MediaType.TEXT_PLAIN)
    public Response set(@FormParam("level") String newLevel) {

        Response.Status httpStatus;
        String json = null;

        try {
            logger.debug("LogLevelWS set operation called");
            MainSettings mainSettings = getCasaSettings();

            if (!mainSettings.getLogLevel().equals(newLevel)) {
                if (SLF4J_LEVELS.contains(newLevel)) {
                    mainSettings.setLogLevel(newLevel);
                    saveSettings(mainSettings);
                    httpStatus = OK;

                } else {
                    httpStatus = BAD_REQUEST;
                    json = String.format("Log level '%s' not recognized", newLevel);
                    logger.warn(json);
                }
            } else {
                httpStatus = OK;
            }

        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

}
