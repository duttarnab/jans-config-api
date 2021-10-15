package io.jans.configapi.plugin.casa.rest;

import com.fasterxml.jackson.core.type.TypeReference;

import io.jans.configapi.filters.ProtectedApi;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.net.URL;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.gluu.casa.conf.MainSettings;

import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.OK;

@ApplicationScoped
@Path("/cors")
@ProtectedApi(scopes = BaseResource.CASA_CONFIG_SCOPE)
public class CORSDomainsResource extends BaseResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response list() {

        Response.Status httpStatus;
        String json = null;

        logger.debug("CORSDomainsWS list operation called");
        try {
            json = mapper.writeValueAsString(getCasaSettings().getCorsDomains());
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
    @Produces(MediaType.TEXT_PLAIN)
    public Response replace(String body) {

        Response.Status httpStatus;
        String json = null;

        logger.debug("CORSDomainsWS replace operation called");
        try {
            MainSettings mainSettings = getCasaSettings();
            List<String> values = mainSettings.getCorsDomains();

            List<String> domains = mapper.readValue(body, new TypeReference<List<String>>(){});
            Set<String> domainSet = new TreeSet();

            for (String dom : domains) {
                try {
                    URL url = new URL(dom);
                    if (url.getProtocol().equals("http") || url.getProtocol().equals("https")) {
                        domainSet.add(dom);
                    }
                } catch (Exception e) {
                    logger.error("Error: " + e.getMessage());
                }
            }
            logger.debug("Resulting domains set: {}", domainSet);

            mainSettings.setCorsDomains(new ArrayList(domainSet));
            logger.debug("Persisting CORS domains in configuration");
            saveSettings(mainSettings);
            httpStatus = OK;

        } catch (Exception e) {
            json = e.getMessage();
            logger.error(json, e);
            httpStatus = INTERNAL_SERVER_ERROR;
        }
        return Response.status(httpStatus).entity(json).build();

    }

}
