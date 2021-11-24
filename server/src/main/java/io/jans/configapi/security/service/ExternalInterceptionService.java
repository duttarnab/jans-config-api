/*
 * Janssen Project software is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.configapi.security.service;

import io.jans.configapi.external.service.ExternalConfigService;
import io.jans.configapi.util.AuthUtil;

import java.io.Serializable;
import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ResourceInfo;
import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;

@ApplicationScoped
@Named("interceptionService")
public class ExternalInterceptionService implements Serializable {

    private static final long serialVersionUID = 4564959567069741194L;

    @Inject
    Logger log;

    @Inject
    ExternalConfigService externalConfigService;

    @Inject
    AuthUtil AuthUtil;


    public boolean authenticate(String token, String issuer, ResourceInfo resourceInfo, String method,
            String path) throws Exception {
        log.debug("Authenticate script params -  token:{}, issuer:{}, resourceInfo:{}, method:{}, path:{} ", token, issuer, resourceInfo, method, path);
        
       if(externalConfigService.isEnabled()) {
           return externalConfigService.executeAuthenticate(token, issuer, resourceInfo, method, path); //TODO
       }
       
       return false;
    }

  
}
