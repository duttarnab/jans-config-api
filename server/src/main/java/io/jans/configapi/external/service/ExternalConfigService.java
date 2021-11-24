/*
 * Janssen Project software is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.configapi.external.service;

import io.jans.configapi.external.context.ConfigAuthContext;
import io.jans.model.SimpleCustomProperty;
import io.jans.model.custom.script.CustomScriptType;
import io.jans.model.custom.script.conf.CustomScriptConfiguration;
import io.jans.model.custom.script.type.configapi.ConfigApiType;
import io.jans.service.custom.script.ExternalScriptService;

import java.util.HashMap;
import java.util.Map;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.container.ResourceInfo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


@ApplicationScoped
public class ExternalConfigService extends ExternalScriptService {

	private static final long serialVersionUID = 1767751544454591666L;
	
	Logger log = LogManager.getLogger(ExternalConfigService.class);

    public ExternalConfigService() {
        super(CustomScriptType.CONFIG_API);
    }

    private CustomScriptConfiguration findConfigWithGEVersion(int version) {
        log.error("ExternalConfigService:::findConfigWithGEVersion() - version =",version);
        return customScriptConfigurations.stream()
                .filter(sc -> executeExternalGetApiVersion(sc) >= version)
                .findFirst().orElse(null);    
    }
    
    private void logAndSave(CustomScriptConfiguration customScriptConfiguration, Exception e) {
        log.error(e.getMessage(), e);
        saveScriptError(customScriptConfiguration.getCustomScript(), e);        
    }

    public boolean executeAuthenticate(String token, String issuer, ResourceInfo resourceInfo, String method,
            String path) {
        log.error("Authenticate script params -  token:{}, issuer:{}, resourceInfo:{}, method:{}, path:{} ", token, issuer, resourceInfo, method, path);
        boolean result = true;
        for (CustomScriptConfiguration customScriptConfiguration : this.customScriptConfigurations) {
            if (customScriptConfiguration.getExternalType().getApiVersion() > 1) {
                ConfigApiType externalType = (ConfigApiType) customScriptConfiguration.getExternalType();            
                ConfigAuthContext context = new ConfigAuthContext(null,token, issuer, resourceInfo, method, path,null); //TODOs
                result &= externalType.authenticate(context);
                
                if (!result) {
                    return result;
                }
            }
        }    
        return result;
    }
    
}
   