package io.jans.configapi.plugin.casa.rest;

import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath("/api/v1/casa")
public class RSApplication extends Application {
    
    @Override
    public Set<Class<?>> getClasses() {
        HashSet<Class<?>> classes = new HashSet<Class<?>>();
        classes.add(CORSDomainsResource.class);
        classes.add(LogLevelResource.class);
        classes.add(OxdResource.class);
        classes.add(PasswordResetAvailResource.class);
        classes.add(SecondFactorResource.class);
        classes.add(StrongAuthnSettingsResource.class);
        return classes;
    }

}
