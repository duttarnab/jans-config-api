package io.jans.configapi.service;

import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.util.Base64Util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
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

    public void importKey(String certFormat,String certPem) throws Exception {
        try {
            log.debug("\n\n KeyStoreService::importKey() - certFormat = " + certFormat
                    + " , certPem = " + certPem);
            if (certFormat == null || certPem == null) {
                throw new WebApplicationException(" CSR PEM is null! ");
            }

            // Get keyStore details
            AppConfiguration appConfiguration = this.getAppConfiguration();
            String keyStoreFile = appConfiguration.getKeyStoreFile();
            String keyStoreSecret = appConfiguration.getKeyStoreSecret();
            log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            // For testing - TBD - Start
            keyStoreFile = "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
            // For testing - TBD - End

            // Get CryptoProvider
            AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " + cryptoProvider);

            // Get keys
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());

           
            //Get Certificate from PEM
            X509Certificate cert = this.x509CertificateFromPem(certPem);
            
            log.debug("\n\n KeyStoreService::importKey() - cert =" + cert);
            PublicKey publicKey = cert.getPublicKey();
            byte[] encodedKey = publicKey.getEncoded();
            log.debug("\n\n KeyStoreService::importKey() - publicKey =" + publicKey+" , encodedKey = "+encodedKey);


            X509Certificate[] certChain = this.getX509CertificateChain(publicKey, dnName, this.getKeyExpirationTime(),
                    cryptoProvider);

            // Generate Kid
            String alias = UUID.randomUUID().toString()
                    + getKidSuffix(Use.SIGNATURE.getParamName(), publicKey.getAlgorithm());
            log.debug("\n\n KeyStoreService::importKey() - alias = " + alias);
            
            // import key
            cryptoProvider.getKeyStore().setKeyEntry(alias, publicKey, keyStoreSecret.toCharArray(), certChain);

            // Verify if key successfully imported
           boolean keyExistsInStore = cryptoProvider.getKeyStore().containsAlias(alias);
            log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" + keyExistsInStore);
        } catch (Exception exp) {
            exp.printStackTrace();
            log.error("Failed to import key", exp);
            throw new WebApplicationException("Error while importing key - " + exp);
        }

    }

    /*
     * public void importKey(String csrPem) throws Exception { try {
     * log.debug("\n\n KeyStoreService::importKey() - csrPem = " + csrPem); if
     * (csrPem == null) { throw new WebApplicationException(" CSR PEM is null! "); }
     * 
     * //1. Convert CSR PEM to X509Certificate X509Certificate cert =
     * x509CertificateFromPem(csrPem);
     * log.debug("\n\n KeyStoreService::importKey() - cert = " + cert);
     * 
     * // Java API requires a certificate chain X509Certificate[] chain = new
     * X509Certificate[1]; chain[0] = cert;
     * 
     * String alias = UUID.randomUUID().toString() +
     * getKidSuffix(cert.getExtendedKeyUsage(), cert.getSigAlgName());
     * log.debug("\n\n KeyStoreService::importKey() - alias = " + alias);
     * 
     * //Get keyStore details AppConfiguration appConfiguration =
     * this.getAppConfiguration(); String keyStoreFile =
     * appConfiguration.getKeyStoreFile(); String keyStoreSecret =
     * appConfiguration.getKeyStoreSecret();
     * log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " +
     * keyStoreFile + " , keyStoreSecret = " + keyStoreSecret);
     * 
     * //Get CryptoProvider AuthCryptoProvider cryptoProvider = new
     * AuthCryptoProvider(keyStoreFile, keyStoreSecret,dnName);
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " +
     * cryptoProvider);
     * 
     * //Get keys
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" +
     * cryptoProvider.getKeys());
     * 
     * //cryptoProvider.keyStore.setKeyEntry(alias, pk,
     * keyStoreSecret.toCharArray(), chain);
     * cryptoProvider.getKeyStore().setCertificateEntry(alias, cert);
     * log.debug("\n\n KeyStoreService::importKey() - Certificate loaded");
     * 
     * //cryptoProvider.getKeyStore().setKeyEntry(alias, cert.getSignature(),
     * chain);
     * 
     * 
     * } catch (Exception exp) { exp.printStackTrace();
     * log.error("Failed to import key", exp); }
     * 
     * }
     */
    private String getKidSuffix(String use, String algorithm) {
        // return "_" + use.getParamName().toLowerCase() + "_" +
        // algorithm.toLowerCase();
        log.debug("\n\n KeyStoreService::getKidSuffix() - use = " + use + " , algorithm = " + algorithm);
        String kid = "";
        if (use != null) {
            kid = kid + "_" + use.toLowerCase();
        }
        if (algorithm != null) {
            kid = kid + "_" + algorithm.toLowerCase();
        }
        log.debug("\n\n KeyStoreService::getKidSuffix() - kid = " + kid);
        return kid;
    }

    public X509Certificate x509CertificateFromPem(String pem) {
        pem = StringUtils.remove(pem, "-----BEGIN CERTIFICATE-----");
        pem = StringUtils.remove(pem, "-----END CERTIFICATE-----");
        return x509CertificateFromBytes(Base64.decode(pem));
    }

    public X509Certificate x509CertificateFromBytes(byte[] cert) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream bais = new ByteArrayInputStream(cert);

            return (X509Certificate) certFactory.generateCertificate(bais);
        } catch (Exception ex) {
            log.error("Failed to parse X.509 certificates from bytes", ex);
        }
        return null;
    }

    /*
     * 
     * private PublicKey getPublicKey() throws Exception { KeyPair keyPair =
     * getKeyPair("RS256");
     * System.out.println("\n\n KeyStoreService::getPublicKey() - keyPair = " +
     * keyPair); PublicKey key = keyPair.getPublic();
     * System.out.println("\n\n KeyStoreService::getPublicKey() - key = " + key);
     * return key;
     * 
     * }
     * 
     * private KeyPair getKeyPair(String strAlgorithm) throws Exception {
     * System.out.println("\n\n KeyStoreService::getKeyPair() - strAlgorithm = " +
     * strAlgorithm);
     * 
     * Algorithm algorithm = Algorithm.fromString(strAlgorithm);
     * System.out.println("\n\n KeyStoreService::getKeyPair() - algorithm = " +
     * algorithm.getParamName());
     * 
     * KeyPairGenerator keyGen = null; SignatureAlgorithm signatureAlgorithm =
     * SignatureAlgorithm.fromString(algorithm.getParamName());
     * 
     * System.out.println("\n\n KeyStoreService::getKeyPair() - algorithm = " +
     * algorithm + " , signatureAlgorithm = " + signatureAlgorithm); if (algorithm
     * == null) { throw new
     * RuntimeException("The signature algorithm parameter cannot be null"); } else
     * if (AlgorithmFamily.RSA.equals(algorithm.getFamily())) { keyGen =
     * KeyPairGenerator.getInstance(algorithm.getFamily().toString(), "BC");
     * keyGen.initialize(2048, new SecureRandom()); } else if
     * (AlgorithmFamily.EC.equals(algorithm.getFamily())) { ECGenParameterSpec
     * eccgen = new ECGenParameterSpec(signatureAlgorithm.getCurve().getAlias());
     * keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(),
     * "BC"); keyGen.initialize(eccgen, new SecureRandom()); } else { throw new
     * RuntimeException("The provided signature algorithm parameter is not supported"
     * ); }
     * 
     * // Generate keyPair KeyPair keyPair = keyGen.generateKeyPair();
     * 
     * System.out.println("\n\n KeyStoreService::getKeyPair() - keyPair = " +
     * keyPair); return keyPair;
     * 
     * }
     */

    /*
     * public void importKey(JSONWebKey jsonWebKey) throws Exception { try {
     * log.debug("\n\n KeyStoreService::importKey() - jsonWebKey = " + jsonWebKey);
     * if (jsonWebKey == null) { throw new
     * WebApplicationException(" No Key to import! "); }
     * 
     * log.
     * debug("\n\n KeyStoreService::importKey() - jsonWebKey.toJSONObject().toString() = "
     * + jsonWebKey.toJSONObject().toString());
     * 
     * //Get keyStore details AppConfiguration appConfiguration =
     * this.getAppConfiguration(); String keyStoreFile =
     * appConfiguration.getKeyStoreFile(); String keyStoreSecret =
     * appConfiguration.getKeyStoreSecret();
     * log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " +
     * keyStoreFile + " , keyStoreSecret = " + keyStoreSecret);
     * 
     * //Get CryptoProvider AuthCryptoProvider cryptoProvider = new
     * AuthCryptoProvider(keyStoreFile, keyStoreSecret,dnName);
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " +
     * cryptoProvider);
     * 
     * //Get keys
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" +
     * cryptoProvider.getKeys());
     * 
     * 
     * //Verify if the store already has the key boolean keyExistsInStore =
     * cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
     * log.debug("\n\n KeyStoreService::importKey() - jsonWebKey.getKid() = " +
     * jsonWebKey.getKid()+" , keyExistsInStore =" + keyExistsInStore);
     * 
     * 
     * log.debug("\n\n KeyStoreService::importKey() - jjsonWebKey.getAlg() =" +
     * jsonWebKey.getAlg() + " , jsonWebKey.toJSONObject().toString() = " +
     * jsonWebKey.toJSONObject().toString());
     * 
     * //Import key if store does not have key if (!keyExistsInStore) {
     * 
     * //Generate private Key KeyPair keyPair =
     * this.getPrivateKey(jsonWebKey.getAlg()); PrivateKey privateKey =
     * keyPair.getPrivate();
     * log.debug("\n\n KeyStoreService::importKey() - privateKey =" + privateKey);
     * 
     * //import key cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(),
     * privateKey, keyStoreSecret.toCharArray(),
     * this.getX509CertificateChain(jsonWebKey,keyPair, dnName,
     * this.getKeyExpirationTime(), cryptoProvider));
     * 
     * }
     * 
     * //Verify if key successfully imported keyExistsInStore =
     * cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
     * log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" +
     * keyExistsInStore);
     * 
     * 
     * } catch (Exception exp) { exp.printStackTrace();
     * log.error("Failed to import key", exp); }
     * 
     * }
     */
    public KeyPair getPrivateKey(String strAlgorithm) throws Exception {

        Algorithm algorithm = Algorithm.fromString(strAlgorithm);

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

        log.debug("\n\n KeyStoreService::getPrivateKey() - keyPair = " + keyPair);
        return keyPair;

    }

    // private X509Certificate[] getX509CertificateChain(KeyPair keyPair, String
    // dnName, Algorithm algorithm,
    // Long expirationTime, AuthCryptoProvider cryptoProvider)
    private X509Certificate[] getX509CertificateChain(PublicKey publicKey, String dnName, Long expirationTime,
            AuthCryptoProvider cryptoProvider) throws CertIOException, OperatorCreationException, CertificateException {

        log.debug("\n\n KeyStoreService::getX509CertificateChain() - publicKey = " + publicKey.toString() + " dnName = "
                + dnName + " , expirationTime = " + expirationTime + " , cryptoProvider = " + cryptoProvider);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(publicKey.getAlgorithm());
        log.trace("\n\n KeyStoreService::getX509CertificateChain() - signatureAlgorithm = " + signatureAlgorithm);

        X509Certificate xcert = this.x509CertificateFromBytes(publicKey.getEncoded());
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = xcert;

        log.debug("\n\n KeyStoreService::getX509CertificateChain() - chain = " + chain);
        return chain;
    }

    private Long getKeyExpirationTime() {
        GregorianCalendar expirationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        expirationTime.add(GregorianCalendar.HOUR, this.getAppConfiguration().getKeyRegenerationInterval());
        expirationTime.add(GregorianCalendar.SECOND, this.getAppConfiguration().getIdTokenLifetime());
        return expirationTime.getTimeInMillis();
    }

}
