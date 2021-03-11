package io.jans.configapi.service;

import io.jans.as.model.config.WebKeysConfiguration;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.exception.InvalidJwtException;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwt.Jwt;
import io.jans.as.model.jwt.JwtClaimName;
import io.jans.as.model.jwt.JwtHeaderName;
import io.jans.as.model.jwk.Algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;

@ApplicationScoped
public class KeyStoreService {
    
    private static String dnName = "CN=Jans Auth CA Certificates";

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
            log.debug("\n\n KeyStoreService::importKey() - jsonWebKey = " + jsonWebKey);
            if (jsonWebKey == null) {
                throw new WebApplicationException(" No Key to import! ");
            }
            
            //Get keyStore details
            AppConfiguration appConfiguration = this.getAppConfiguration();
            log.debug("\n\n KeyStoreService::importKey() - appConfiguration = " + appConfiguration);
            String keyStoreFile = appConfiguration.getKeyStoreFile();
            String keyStoreSecret = appConfiguration.getKeyStoreSecret();
            log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            //For local testing - TBD
            keyStoreFile = "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
            log.debug("\n\n KeyStoreService::importKey() - 2 - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            //Get CryptoProvider
            AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret,dnName);                    
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " + cryptoProvider);

            //Get keyss
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());

       
            //Verify if the store already has the key 
            log.debug("\n\n KeyStoreService::importKey() - jsonWebKey.getKid() =" + jsonWebKey.getKid());
            boolean conatinsKeys = cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
            log.debug("\n\n KeyStoreService::importKey() - conatinsKeys =" + conatinsKeys);
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.containsKey(jsonWebKey.getKid()) ="
                    + cryptoProvider.containsKey(jsonWebKey.getKid()));

            // For testing -- Delete later Start - TBD
            boolean deleteKeyStatus = cryptoProvider.deleteKey(jsonWebKey.getKid());
            log.debug("\n\n KeyStoreService::importKey() - jsonWebKey.getKid() =" + jsonWebKey.getKid()
                    + " , deleteKeyStatus = " + deleteKeyStatus);
            conatinsKeys = cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
            log.debug("\n\n KeyStoreService::importKey() - conatinsKeys 2 =" + conatinsKeys);
            // For testing -- Delete later - End - TBD

            log.debug("\n\n KeyStoreService::importKey() - jjsonWebKey.getAlg() =" + jsonWebKey.getAlg()
                    + " , jsonWebKey.toJSONObject().toString() = " + jsonWebKey.toJSONObject().toString());
            if (!conatinsKeys) {
                
                //Generate private Key
                KeyPair keyPair = this.getPrivateKey(jsonWebKey.getAlg());
                PrivateKey privateKey = keyPair.getPrivate();
                log.debug("\n\n KeyStoreService::importKey() - privateKey =" + privateKey);
                
                //import key
                cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(), privateKey,
                        keyStoreSecret.toCharArray(), this.getX509CertificateChain(keyPair, dnName, jsonWebKey.getAlg(), this.getKeyExpirationTime(), cryptoProvider));
                // cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(),
                // jsonWebKey.toJSONObject().toString().getBytes(), null);
            }
            
            //Verify if key successfully imported 
            conatinsKeys = cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
            log.debug("\n\n KeyStoreService::importKey() - conatinsKeys 3 =" + conatinsKeys);
            

        } catch (Exception exp) {
            exp.printStackTrace();
            log.error("Failed to import key", exp);
        }

    }

    public KeyPair getPrivateKey(Algorithm algorithm) throws Exception {
        log.debug("\n\n KeyStoreService::generateKey() - algorithm = " + algorithm);

        KeyPairGenerator keyGen = null;
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());

        log.debug("\n\n KeyStoreService::getPrivateKey() - algorithm = " + algorithm + " , signatureAlgorithm = "
                + signatureAlgorithm);
        if (algorithm == null) {
            throw new RuntimeException("The signature algorithm parameter cannot be null");
        } else if (AlgorithmFamily.RSA.equals(algorithm.getFamily())) {
            keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(), "BC");
            keyGen.initialize(2048, new SecureRandom());
        } else if (AlgorithmFamily.EC.equals(algorithm.getFamily())) {
            ECGenParameterSpec eccgen = new ECGenParameterSpec(signatureAlgorithm.getCurve().getAlias());
            keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(), "BC");
            keyGen.initialize(eccgen, new SecureRandom());
        } else {
            throw new RuntimeException("The provided signature algorithm parameter is not supported");
        }

        // Generate the key
        KeyPair keyPair = keyGen.generateKeyPair();
       // PrivateKey privateKey = keyPair.getPrivate();

        log.debug("\n\n KeyStoreService::getPrivateKey() - keyPair = " + keyPair);
        return keyPair;

    }

    private X509Certificate[] getX509CertificateChain(KeyPair keyPair, String dnName, Algorithm algorithm,
            Long expirationTime, AuthCryptoProvider cryptoProvider)
            throws CertIOException, OperatorCreationException, CertificateException {
        
        log.debug("\n\n KeyStoreService::getX509CertificateChain() - keyPair = " + keyPair + " , dnName = "
                + dnName+" , algorithm = "+algorithm+" , cryptoProvider = "+cryptoProvider);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());
        log.debug("\n\n KeyStoreService::getX509CertificateChain() - algorithm = " + algorithm + " , signatureAlgorithm = "
                + signatureAlgorithm);
        // Java API requires a certificate chain
        X509Certificate cert = cryptoProvider.generateV3Certificate(keyPair, dnName, signatureAlgorithm.getAlgorithm(),
                expirationTime);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        log.debug("\n\n KeyStoreService::getX509CertificateChain() - chain = "+chain);
        return chain;
    }
    
    private Long getKeyExpirationTime() {
        GregorianCalendar expirationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        expirationTime.add(GregorianCalendar.HOUR, this.getAppConfiguration().getKeyRegenerationInterval());
        expirationTime.add(GregorianCalendar.SECOND, this.getAppConfiguration().getIdTokenLifetime());
        return expirationTime.getTimeInMillis();
    }

}
