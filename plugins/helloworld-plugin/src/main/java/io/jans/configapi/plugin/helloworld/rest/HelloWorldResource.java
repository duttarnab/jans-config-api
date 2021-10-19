package io.jans.configapi.plugin.helloworld.rest;

import org.slf4j.Logger;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/admin-ui/logging")
public class HelloWorldResource {
    static final String SAY_HELLO = "/hello";

    @Inject
    Logger log;

    @GET
    @Path(SAY_HELLO)
    @Produces(MediaType.APPLICATION_JSON)
    public Response helloWorld() {
        try {
            return Response.ok("Hello World!").build();
        } catch (Exception e) {
            return Response.serverError().entity(e.getMessage()).build();
        }
    }
}
