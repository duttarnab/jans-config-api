package io.jans.configapi.service;

import io.jans.as.model.config.WebKeysConfiguration;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;

import org.slf4j.Logger;

@ApplicationScoped
public class KeystoreService {

    @Inject
    Logger log;

    @Inject
    ConfigurationService configurationService;

    private AppConfiguration getAppConfiguration() {
        AppConfiguration appConfiguration = configurationService.find();
        return appConfiguration;
    }

    public void importKey(JSONWebKey jsonWebKey) throws Exception {
        try {
            log.debug("\n\n KeystoreService::importKey() - jsonWebKey = " + jsonWebKey);
            AppConfiguration appConfiguration = this.getAppConfiguration();
            log.debug("\n\n KeystoreService::importKey() - appConfiguration = " + appConfiguration);
            String keyStoreFile = appConfiguration.getKeyStoreFile();
            String keyStoreSecret = appConfiguration.getKeyStoreSecret();
            log.debug("\n\n KeystoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            //keyStoreFile = "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
            log.debug("\n\n KeystoreService::importKey() - 2 - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret,
                    "CN=Jans Auth CA Certificates");
            log.debug("\n\n KeystoreService::importKey() - cryptoProvider = " + cryptoProvider);

            // import key
            log.debug("\n\n KeystoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());
            
            if(jsonWebKey == null)
            {
                throw new WebApplicationException(" No Key to import! ");
            }
            

            log.debug("\n\n KeystoreService::importKey() - jsonWebKey.getKid() =" + jsonWebKey.getKid());
            boolean conatinsKeys = cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
            log.debug("\n\n KeystoreService::importKey() - conatinsKeys =" + conatinsKeys);

            log.debug("\n\n KeystoreService::importKey() - cryptoProvider.containsKey(jsonWebKey.getKid()) =" + cryptoProvider.containsKey(jsonWebKey.getKid()));

            if (!conatinsKeys) {
               cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(), jsonWebKey.toJSONObject().toString().getBytes(), null);
            }

        } catch (Exception exp) {
            exp.printStackTrace();
            log.error("Failed to import key", exp);
        }

    }

}
