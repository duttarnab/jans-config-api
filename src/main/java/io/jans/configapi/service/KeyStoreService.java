package io.jans.configapi.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.google.common.base.Preconditions;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.config.Conf;
import io.jans.as.model.config.WebKeysConfiguration;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.jwk.KeyType;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import static io.jans.as.model.jwk.JWKParameter.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.List;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

@ApplicationScoped
public class KeyStoreService {

    private static String DN_NAME = "CN=Jans Auth CA Certificates";
    private static int KEY_LENGTH = 2048;

    @Inject
    Logger log;

    @Inject
    ConfigurationService configurationService;

    private HashMap<String, String> algorithmMap = new HashMap();
    {
        algorithmMap.put("SHA256WITHRSA", "RS256");
        algorithmMap.put("SHA384WITHRSA", "RS384");
        algorithmMap.put("SHA512WITHRSA", "RS512");
        algorithmMap.put("SHA256WITHECDSA", "ES256");
        algorithmMap.put("SHA384WITHECDSA", "ES384");
        algorithmMap.put("SHA512WITHECDSA", "ES512");
        algorithmMap.put("SHA256withRSAandMGF1", "PS256");
        algorithmMap.put("SHA384withRSAandMGF1", "PS384");
        algorithmMap.put("SHA512withRSAandMGF1", "PS512");

    }

    private AppConfiguration getAppConfiguration() {
        AppConfiguration appConfiguration = configurationService.find();
        return appConfiguration;
    }

    private static KeyPair generateRsaKeyPair(int keylengthInt) throws NoSuchAlgorithmException {
        KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
        keypairGenerator.initialize(keylengthInt, new SecureRandom());
        return keypairGenerator.generateKeyPair();
    }
    
    public AuthCryptoProvider getAuthCryptoProvider() throws Exception {
        log.debug("\n\n KeyStoreService::getAuthCryptoProvider() - Entry \n\n");
        // Get keyStore details
        AppConfiguration appConfiguration = this.getAppConfiguration();
        String keyStoreFile = appConfiguration.getKeyStoreFile();
        String keyStoreSecret = appConfiguration.getKeyStoreSecret();
        log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                + keyStoreSecret);

        // For testing - TBD - Start
        keyStoreFile = "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
        // For testing - TBD - End

        // Get handle to KeyStore
        AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, DN_NAME);
        log.debug("\n\n KeyStoreService::getAuthCryptoProvider() - cryptoProvider = " + cryptoProvider);
        /*
        java.util.List<String> keys = cryptoProvider.getKeys();
        log.debug("\n\n KeyStoreService::getAuthCryptoProvider() - cryptoProvider.getKeys() = "
                + cryptoProvider.getKeys() + "\n\n");

        for (int i = 0; i < keys.size(); i++) {
            System.out.println("\n keys = " + keys.get(i) + "\n\n");

            String alias = (String) keys.get(i);
            // To test
            // alias = "47d65f1d-66f1-4b4a-92ec-d969522f4cbc_sig_rs256";

            PrivateKey privateKey = cryptoProvider.getPrivateKey(alias);
            System.out.println("\n\n KeyStoreService::getAuthCryptoProvider() - privateKey = " + privateKey + "\n\n");

            PublicKey publicKey = cryptoProvider.getPublicKey(alias);
            System.out.println("\n\n KeyStoreService::getAuthCryptoProvider() - publicKey = " + publicKey + "\n\n");
        }
       
         */
        return cryptoProvider;

    }

    public void importPublicKey(JSONWebKey jsonWebKey) throws Exception {
        try {
            log.info("\n\n KeyStoreService::importPublicKey() - jsonWebKey = " + jsonWebKey+"\n\n\n");

            // Validate input
            Preconditions.checkNotNull(jsonWebKey, "JWK Key cannot be null !!!");
            JSONObject jsonObj =  jsonWebKey.toJSONObject();
            log.info("\n\n KeyStoreService::importPublicKey() - jsonObj = " + jsonObj);
            
            Algorithm algorithm = jsonWebKey.getAlg();
            JWK jwk = null;
            PrivateKey key = null;
            X509Certificate[] chain = null;
            if (algorithm == null) {
                throw new RuntimeException("The signature algorithm parameter cannot be null");
            } else if (AlgorithmFamily.RSA.equals(algorithm.getFamily())) {
                 jwk = JWK.parse(jsonObj.toString());
                 key = jwk.toRSAKey().toPrivateKey();
            } else if (AlgorithmFamily.EC.equals(algorithm.getFamily())) {
                jwk = (ECKey) JWK.parse(jsonObj.toString());
                key = jwk.toECKey().toPrivateKey();
            } else {
                throw new RuntimeException("The provided algorithm parameter is not supported");
            }
            
            log.info("\n\n KeyStoreService::importPublicKey() - jwk.getKeyID() = " + jwk.getKeyID()
                + " , jwk.getKeyType() = "+jwk.getKeyType()
                + " , jwk.getAlgorithm() = "+jwk.getAlgorithm()
                + " , jwk.getKeyUse() = "+jwk.getKeyUse()
                + " , jwk.getKeyOperations() = "+jwk.getKeyOperations()
                + " , jwk.getParsedX509CertChain() = "+jwk.getParsedX509CertChain()
                + " , jwk.getX509CertChain() = "+jwk.getX509CertChain()
                + " , jwk.getX509CertURL() = "+jwk.getX509CertURL()
                + " , jwk.isPrivate()= "+jwk.isPrivate()
                + " , jwk.toJSONObject()= "+jwk.toJSONObject()
                
            );
            log.info("\n\n KeyStoreService::importPublicKey() - key = "+key
            + " , key.getAlgorithm() = "+key.getAlgorithm()
            + " , key.getEncoded() = "+key.getEncoded()
            + " , key.getFormat() = "+key.getFormat()
            + " , key.toString() = "+key.toString()
            );
            
            // Get handle to KeyStore
            AuthCryptoProvider cryptoProvider = getAuthCryptoProvider();
            log.info("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());

            // Get keyStore details
            AppConfiguration appConfiguration = this.getAppConfiguration();
            String keyStoreFile = appConfiguration.getKeyStoreFile();
            String keyStoreSecret = appConfiguration.getKeyStoreSecret();
            log.info("\n\n KeyStoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            // For testing - TBD - Start
            jsonWebKey.setKid("PUJATEST123");
            keyStoreFile = "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
            // For testing - TBD - End

            // Verify if the store already has the key
            boolean keyExistsInStore = cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
            log.info("\n\n KeyStoreService::importKey() - jsonWebKey.getKid() = " + jsonWebKey.getKid()
                    + " , keyExistsInStore =" + keyExistsInStore);

            log.info("\n\n KeyStoreService::importKey() - jjsonWebKey.getAlg() =" + jsonWebKey.getAlg()
                    + " , jsonWebKey.toJSONObject().toString() = " + jsonWebKey.toJSONObject().toString());

            // Import key if store does not have key
            if (!keyExistsInStore) {
               //import key
               cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(),key, keyStoreSecret.toCharArray(), this.getX509CertificateChain(jwk));
                
            }

            // Verify if key successfully imported
            keyExistsInStore = cryptoProvider.getKeyStore().containsAlias(jsonWebKey.getKid());
            log.info("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" + keyExistsInStore);

            // Update Jwks
            /*
            Conf conf = configurationService.findConf();
            WebKeysConfiguration webkeys = configurationService.findConf().getWebKeys();
            log.debug("\n\n KeyStoreService::importKey() - webkeys before update =" + webkeys.toString());
            webkeys.getKeys().add(jsonWebKey);
            conf.setWebKeys(webkeys);
            configurationService.merge(conf);
            webkeys = configurationService.findConf().getWebKeys();
            
            log.debug("\n\n KeyStoreService::importKey() - webkeys after update =" + webkeys.toString());
            */

        } catch (Exception exp) {
            exp.printStackTrace();
            log.error("Failed to import key", exp);
            throw new WebApplicationException("Error while importing key - " + exp);
        }

    }
    
    private X509Certificate[] getX509CertificateChain(JWK key)
            throws JOSEException {
        
        log.info("\n\n KeyStoreService::getX509CertificateChain() - key = " + key);
        
        List<X509Certificate> certList = key.getParsedX509CertChain().stream().map(x -> x).collect(Collectors.toList());
        X509Certificate[] chain = certList.toArray(new X509Certificate[certList.size()]);

       
        log.info("\n\n KeyStoreService::getX509CertificateChain() - chain = " + chain);
        
        return chain;
    }
    
    private KeyPair generateKeyPair(Algorithm algorithm, Long expirationTime, Use use,int keylength) throws Exception {
        log.debug("\n\n KeyStoreService::generateKeyPair() - Entry \n\n");

        KeyPairGenerator keyGen = null;

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());
        if (signatureAlgorithm == null) {
            signatureAlgorithm = SignatureAlgorithm.RS256;
        }

        if (algorithm == null) {
            throw new RuntimeException("The signature algorithm parameter cannot be null");
        } else if (AlgorithmFamily.RSA.equals(algorithm.getFamily())) {
            keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(), "BC");
            keyGen.initialize(keylength, new SecureRandom());
        } else if (AlgorithmFamily.EC.equals(algorithm.getFamily())) {
            ECGenParameterSpec eccgen = new ECGenParameterSpec(signatureAlgorithm.getCurve().getAlias());
            keyGen = KeyPairGenerator.getInstance(algorithm.getFamily().toString(), "BC");
            keyGen.initialize(eccgen, new SecureRandom());
        } else {
            throw new RuntimeException("The provided signature algorithm parameter is not supported");
        }

        // Generate the key
        KeyPair keyPair = keyGen.generateKeyPair();
        log.debug("\n\n KeyStoreService::generateKeyPair() - Exit - keyPair = "+keyPair+"\n\n");
        return keyPair;
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

        log.debug("\n\n KeyStoreService::getPrivateKey() - keyPair = " + keyPair);
        return keyPair;

    }
    
    

    private X509Certificate[] getX509CertificateChain(KeyPair keyPair, String dnName, Algorithm algorithm,
            Long expirationTime, AuthCryptoProvider cryptoProvider)
            throws CertIOException, OperatorCreationException, CertificateException {
        
        log.debug("\n\n KeyStoreService::getX509CertificateChain() - keyPair = " + keyPair + " , dnName = "
                + dnName+" , algorithm = "+algorithm+" , cryptoProvider = "+cryptoProvider);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());
        log.trace("\n\n KeyStoreService::getX509CertificateChain() - algorithm = " + algorithm + " , signatureAlgorithm = "
                + signatureAlgorithm);
        // Java API requires a certificate chain
        X509Certificate cert = cryptoProvider.generateV3Certificate(keyPair, dnName, signatureAlgorithm.getAlgorithm(),
                expirationTime);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        log.debug("\n\n KeyStoreService::getX509CertificateChain() - chain = "+chain);
        return chain;
    }
  
    public void importKey(String format, String alias, String certificateStr, String privateKeyStr) throws Exception {
        try {
            log.debug("\n\n KeyStoreService::importKey() - format = " + format + " , alias = " + alias
                    + ", certificateStr = " + certificateStr + " ,privateKeyStr = " + privateKeyStr);

            // Validate input
            Preconditions.checkNotNull(format, "Format cannot be null !!!");
            Preconditions.checkNotNull(alias, "Alias cannot be null !!!");
            Preconditions.checkNotNull(certificateStr, "Certificate cannot be null !!!");
            Preconditions.checkNotNull(privateKeyStr, "Private Key cannot be null !!!");

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = this.x509CertificateFromPem(certificateStr);
            log.debug("\n\n KeyStoreService::importKey() - cert =" + cert);

            log.debug("\n\n KeyStoreService::importKey() - cert.getSigAlgName() =" + cert.getSigAlgName()
                    + " , cert.getPublicKey().getAlgorithm() = " + cert.getPublicKey().getAlgorithm());

            String algorithmStr = algorithmMap.get(cert.getSigAlgName().toUpperCase());
            log.debug("\n\n KeyStoreService::importKey() - algorithmStr =" + algorithmStr + " ,algorithmMap = "
                    + algorithmMap);
            if (algorithmStr == null) {
                throw new WebApplicationException("Certificate Algorithm - (" + cert.getSigAlgName() + ") not found!");
            }

            // Get Key chain
            X509Certificate[] certChain = new X509Certificate[1];
            certChain[0] = cert;
            log.debug("\n\n KeyStoreService::importKey() - certChain = " + certChain);

            // Get Public Key
            PublicKey publicKey = cert.getPublicKey();
            byte[] encodedKey = publicKey.getEncoded();
            log.debug("\n\n KeyStoreService::importKey() - publicKey =" + publicKey + " , publicKey.getAlgorithm() = "
                    + publicKey.getAlgorithm() + " , publicKey.getFormat() = " + publicKey.getFormat()
                    + " , encodedKey = " + encodedKey);

            // Get Private Key
            byte[] encoded = getKeyFromPem(privateKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance(publicKey.getAlgorithm());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            log.debug("\n\n KeyStoreService::importKey() - privateKey =" + privateKey.getEncoded());

            // Get keyStore details
            AppConfiguration appConfiguration = this.getAppConfiguration();
            String keyStoreFile = appConfiguration.getKeyStoreFile();
            String keyStoreSecret = appConfiguration.getKeyStoreSecret();
            log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = "
                    + keyStoreSecret);

            // For testing - TBD - Start
            keyStoreFile = "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
            // For testing - TBD - End

            // Get handle to KeyStore
            AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, DN_NAME);
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " + cryptoProvider);

            // Get keys
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());

            // Generate JWK
            // JSONWebKeySet jwks = this.generateKeys(cryptoProvider, algorithmStr,
            // algorithmStr);

            // import
            // cryptoProvider.getKeyStore().setKeyEntry(alias, publicKey,
            // keyStoreSecret.toCharArray(), null);
            JSONWebKey jsonWebKey = generateSigningKey(cryptoProvider, algorithmStr);

            cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(), privateKey, keyStoreSecret.toCharArray(),
                    certChain);

            // Verify if key successfully imported
            boolean keyExistsInStore = cryptoProvider.getKeyStore().containsAlias(alias);
            log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" + keyExistsInStore);

            // Update Jwks
            Conf conf = configurationService.findConf();
            WebKeysConfiguration webkeys = configurationService.findConf().getWebKeys();
            log.debug("\n\n KeyStoreService::importKey() - webkeys before update =" + webkeys.toString());
            webkeys.getKeys().add(jsonWebKey);
            conf.setWebKeys(webkeys);
            configurationService.merge(conf);
            webkeys = configurationService.findConf().getWebKeys();
            log.debug("\n\n KeyStoreService::importKey() - webkeys after update =" + webkeys.toString());

        } catch (Exception exp) {
            exp.printStackTrace();
            log.error("Failed to import key", exp);
            throw new WebApplicationException("Error while importing key - " + exp);
        }

    }

    private JSONWebKey generateSigningKey(AbstractCryptoProvider cryptoProvider, String strSignatureAlgorithm)
            throws Exception, JSONException {
        log.debug("\n\n KeyStoreService::generateSigningKey() - cryptoProvider: {}, strSignatureAlgorithm: {}",
                cryptoProvider, strSignatureAlgorithm);
        // Generate Key set
        JSONWebKeySet jwks = new JSONWebKeySet();

        // ??????//this.getKeyExpirationTime(); // ??? TBD as Keys do not have expiry
        // details ???

        Algorithm algorithm = Algorithm.fromString(strSignatureAlgorithm);
        log.debug("\n\n KeyStoreService::generateSigningKey() - algorithm = " + algorithm);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.name());
        log.debug("\n\n KeyStoreService::generateSigningKey() - signatureAlgorithm = " + signatureAlgorithm);

        JSONObject result = cryptoProvider.generateKey(algorithm, this.getKeyExpirationTime(), Use.SIGNATURE);
        log.debug("\n\n KeyStoreService::generateSigningKey() - result = " + result);

        JSONWebKey key = new JSONWebKey();
        key.setKid(result.getString(KEY_ID));
        key.setUse(Use.SIGNATURE);
        key.setAlg(algorithm);
        key.setKty(KeyType.fromString(signatureAlgorithm.getFamily().toString()));
        key.setExp(result.optLong(EXPIRATION_TIME));
        key.setCrv(signatureAlgorithm.getCurve());
        key.setN(result.optString(MODULUS));
        key.setE(result.optString(EXPONENT));
        key.setX(result.optString(X));
        key.setY(result.optString(Y));

        JSONArray x5c = result.optJSONArray(CERTIFICATE_CHAIN);
        key.setX5c(io.jans.as.model.util.StringUtils.toList(x5c));

        log.debug("\n\n KeyStoreService::generateSigningKey() - key = " + key);
        System.out.println(key);
        return key;

    }

    private JSONWebKeySet generateKeys(AbstractCryptoProvider cryptoProvider, String strSignatureAlgorithm,
            String strEncryptionAlgorithm) throws Exception, JSONException {

        log.debug(
                "\n\n KeyStoreService::generateKeys() - cryptoProvider: {}, strSignatureAlgorithm: {}, strEncryptionAlgorithm: {} ",
                cryptoProvider, strSignatureAlgorithm, strEncryptionAlgorithm);
        // Generate Key set
        JSONWebKeySet jwks = new JSONWebKeySet();

        // ??????//this.getKeyExpirationTime(); // ??? TBD as Keys do not have expiry
        // details ???

        Algorithm algorithm = Algorithm.fromString(strSignatureAlgorithm);
        log.debug("\n\n KeyStoreService::generateKeys() - algorithm = " + algorithm);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.name());
        log.debug("\n\n KeyStoreService::generateKeys() - signatureAlgorithm = " + signatureAlgorithm);

        JSONObject result = cryptoProvider.generateKey(algorithm, this.getKeyExpirationTime(), Use.SIGNATURE);
        log.debug("\n\n KeyStoreService::generateKeys() - result = " + result);

        JSONWebKey key = new JSONWebKey();
        key.setKid(result.getString(KEY_ID));
        key.setUse(Use.SIGNATURE);
        key.setAlg(algorithm);
        key.setKty(KeyType.fromString(signatureAlgorithm.getFamily().toString()));
        key.setExp(result.optLong(EXPIRATION_TIME));
        key.setCrv(signatureAlgorithm.getCurve());
        key.setN(result.optString(MODULUS));
        key.setE(result.optString(EXPONENT));
        key.setX(result.optString(X));
        key.setY(result.optString(Y));

        JSONArray x5c = result.optJSONArray(CERTIFICATE_CHAIN);
        key.setX5c(io.jans.as.model.util.StringUtils.toList(x5c));

        jwks.getKeys().add(key);

        // TBD for testing - Start ???
        // This is giving error as neither cert or the public key has Encryption
        // details????????????
        algorithm = Algorithm.fromString(strEncryptionAlgorithm);
        log.debug("\n\n KeyStoreService::generateKeys() - algorithm = " + algorithm);
        KeyEncryptionAlgorithm encryptionAlgorithm = KeyEncryptionAlgorithm.fromName(algorithm.getParamName());
        log.debug("\n\n KeyStoreService::generateKeys() - encryptionAlgorithm = " + encryptionAlgorithm);
        result = cryptoProvider.generateKey(algorithm, this.getKeyExpirationTime(), Use.ENCRYPTION);

        key = new JSONWebKey();
        key.setKid(result.getString(KEY_ID));
        key.setUse(Use.ENCRYPTION);
        key.setAlg(algorithm);
        key.setKty(KeyType.fromString(encryptionAlgorithm.getFamily()));
        key.setExp(result.optLong(EXPIRATION_TIME));
        key.setN(result.optString(MODULUS));
        key.setE(result.optString(EXPONENT));
        key.setX(result.optString(X));
        key.setY(result.optString(Y));

        x5c = result.optJSONArray(CERTIFICATE_CHAIN);
        key.setX5c(io.jans.as.model.util.StringUtils.toList(x5c));

        jwks.getKeys().add(key);

        log.debug("\n\n KeyStoreService::generateKeys() - jwks = " + jwks);
        System.out.println(jwks);
        return jwks;
    }

    private X509Certificate x509CertificateFromPem(String pem) {
        pem = StringUtils.remove(pem, "-----BEGIN CERTIFICATE-----");
        pem = StringUtils.remove(pem, "-----END CERTIFICATE-----");
        return x509CertificateFromBytes(Base64.decode(pem));
    }

    private byte[] getKeyFromPem(String pem) {
        pem = StringUtils.remove(pem, "-----BEGIN PRIVATE KEY-----");
        pem = StringUtils.remove(pem, "-----END PRIVATE KEY-----");
        return (Base64.decode(pem));
    }

    private X509Certificate x509CertificateFromBytes(byte[] cert) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream bais = new ByteArrayInputStream(cert);
            return (X509Certificate) certFactory.generateCertificate(bais);
        } catch (Exception ex) {
            log.error("Failed to parse X.509 certificates from bytes", ex);
        }
        return null;
    }

    private Long getKeyExpirationTime() {
        GregorianCalendar expirationTime = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        expirationTime.add(GregorianCalendar.HOUR, this.getAppConfiguration().getKeyRegenerationInterval());
        expirationTime.add(GregorianCalendar.SECOND, this.getAppConfiguration().getIdTokenLifetime());
        return expirationTime.getTimeInMillis();
    }

}
