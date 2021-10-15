package io.jans.configapi.plugin.casa.rest;

import io.jans.configapi.filters.ProtectedApi;
import io.jans.configapi.plugin.casa.service.SecondFactorService;

import java.util.List;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.gluu.casa.model.User;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.OK;

@ApplicationScoped
@Path("/2fa")
@ProtectedApi(scopes = BaseResource.CASA_2FA_SCOPE)
public class SecondFactorResource extends BaseResource {

    @Inject
    private SecondFactorService sfService;

    @GET
    @Path("users")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveUsers(@QueryParam("pattern") String searchPattern) {

        Response.Status httpStatus;
        String json = null;

        logger.debug("SecondFactorResource retrieveUsers operation called");
        try {            
            if (StringUtils.isEmpty(searchPattern)) {
                json = "No search pattern";
                logger.warn(json);
                httpStatus = BAD_REQUEST;

            } else {
                List<User> result = sfService.searchUsers2FAEnabled(searchPattern);
                json = mapper.writeValueAsString(result);
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
    @Path("turn-off")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response disable2FA(List<String> userIds) {

        Response.Status httpStatus;
        String json = null;

        logger.debug("SecondFactorResource disable2FA operation called");
        try {
            if (userIds != null && !userIds.isEmpty()) {
                List<String> inums = sfService.disable2FAFor(userIds);
                logger.debug("2FA disabled for {} users", inums.size());
                json = mapper.writeValueAsString(inums);
            }
            httpStatus = OK;

        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();       

    }

}
