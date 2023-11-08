package com.partitio.vyos.controller;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.resteasy.reactive.RestForm;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

@RegisterRestClient
public interface VyOSQuerier {

    @POST
    @Path("/retrieve")
    @Consumes("application/x-www-form-urlencoded")
    public Response getConfiguration(@RestForm("key") String key, @RestForm("data") Object data);

    @POST
    @Path("/configure")
    @Consumes("application/x-www-form-urlencoded")
    public Response configure(@RestForm("key") String key, @RestForm("data") Object data);
}
