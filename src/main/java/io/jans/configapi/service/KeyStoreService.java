package io.jans.configapi.service;

import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.ElevenCryptoProvider;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.configuration.AppConfiguration;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.jwk.KeyType;
import io.jans.as.model.jwk.JSONWebKey;
import io.jans.as.model.jwk.JSONWebKeySet;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import io.jans.configapi.rest.model.ClientCertificate;

import static io.jans.as.model.jwk.JWKParameter.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Calendar;
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
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;

import com.google.common.base.Preconditions;

@ApplicationScoped
public class KeyStoreService {

    private static String dnName = "CN=Jans Auth CA Certificates";

    @Inject
    Logger log;

    @Inject
    ConfigurationService configurationService;
    
    private HashMap<String,String> algorithmMap = new HashMap();
    {
        algorithmMap.put("SHA256WITHRSA","RS256");
        algorithmMap.put("SHA384WITHRSA","RS384");
        algorithmMap.put("SHA512WITHRSA","RS512");
        algorithmMap.put("SHA256WITHECDSA","ES256");
        algorithmMap.put("SHA384WITHECDSA","ES384");
        algorithmMap.put("SHA512WITHECDSA","ES512");
        algorithmMap.put("SHA256withRSAandMGF1","PS256");
        algorithmMap.put("SHA384withRSAandMGF1","PS384");
        algorithmMap.put("SHA512withRSAandMGF1","PS512");

    }
    

    private AppConfiguration getAppConfiguration() {
        AppConfiguration appConfiguration = configurationService.find();
        return appConfiguration;
    }

    private void validateClientCertificate(ClientCertificate clientCertificate) {
        Preconditions.checkNotNull(clientCertificate, "Client Certificate cannot be null !!!");
        Preconditions.checkNotNull(clientCertificate.getAlias(), "Alias cannot be null !!!");
        Preconditions.checkNotNull(clientCertificate.getFormat(), "Format cannot be null !!!");
        Preconditions.checkNotNull(clientCertificate.getCert(), "Certificate cannot be null !!!");
        Preconditions.checkNotNull(clientCertificate.getPrivateKey(), "Private Key cannot be null !!!");
        Preconditions.checkNotNull(clientCertificate.getPublicKey(), "Public Key cannot be null !!!");
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
            +" , cert.getPublicKey().getAlgorithm() = "+cert.getPublicKey().getAlgorithm()
            );
            
            String algorithmStr = algorithmMap.get(cert.getSigAlgName().toUpperCase());
            log.debug("\n\n KeyStoreService::importKey() - algorithmStr =" + algorithmStr +" ,algorithmMap = "+algorithmMap);
            if(algorithmStr == null) {
                throw new WebApplicationException("Certificate Algorithm - ("+cert.getSigAlgName()+") not found!");
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

            // Get CryptoProvider
            AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " + cryptoProvider);

            // Get keys
            log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());

            // Generate JWK
           // JSONWebKeySet jwks = this.generateKeys(cryptoProvider, algorithmStr, algorithmStr);

            // import
            //cryptoProvider.getKeyStore().setKeyEntry(alias, publicKey, keyStoreSecret.toCharArray(), null);

            JSONWebKey jsonWebKey = generateSigningKey(cryptoProvider, algorithmStr);
                     
            cryptoProvider.getKeyStore().setKeyEntry(jsonWebKey.getKid(), privateKey,
                    keyStoreSecret.toCharArray(), certChain);


            // Verify if key successfully imported
            boolean keyExistsInStore = cryptoProvider.getKeyStore().containsAlias(alias);

            // Update Jwks

            log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" + keyExistsInStore);
        } catch (Exception exp) {
            exp.printStackTrace();
            log.error("Failed to import key", exp);
            throw new WebApplicationException("Error while importing key - " + exp);
        }

    }

    /*
     * public void importKey1(String format, String alias, String key) throws
     * Exception { try { log.debug("\n\n KeyStoreService::importKey() - format = " +
     * format+" , alias = "+alias+", key = "+key);
     * 
     * // Validate cert Preconditions.checkNotNull(format,
     * "Format cannot be null !!!"); Preconditions.checkNotNull(key,
     * "Key cannot be null !!!");
     * 
     * byte[] publicKeyBytes = parseDERFromPEM(key, "-----BEGIN PUBLIC KEY-----",
     * "-----END PUBLIC KEY-----"); byte[] privateKeyBytes = parseDERFromPEM(key,
     * "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
     * 
     * if(publicKeyBytes == null || privateKeyBytes == null) { throw new
     * WebApplicationException("Both Public and Private Keys required!"); }
     * log.debug("\n\n KeyStoreService::importKey() - publicKeyBytes = "
     * +publicKeyBytes+" , privateKeyBytes = "+privateKeyBytes);
     * 
     * // Get Public Key PublicKey publicKey =
     * this.generatePublicKey(publicKeyBytes);
     * log.debug("\n\n KeyStoreService::importKey() - publicKey =" + publicKey +
     * " , publicKey.getAlgorithm() = " + publicKey.getAlgorithm() +
     * " , publicKey.getFormat() = " + publicKey.getFormat() +
     * " , publicKey.getEncoded() = " + publicKey.getEncoded() );
     * 
     * 
     * // Get Private Key PrivateKey privateKey =
     * this.generatePrivateKey(privateKeyBytes);
     * log.debug("\n\n KeyStoreService::importKey() - privateKey =" + privateKey +
     * " , privateKey.getAlgorithm() = " + privateKey.getAlgorithm() +
     * " , privateKey.getFormat() = " + privateKey.getFormat() +
     * " , privateKey.getEncoded() = " + privateKey.getEncoded() );
     * 
     * if( publicKey.getAlgorithm().isEmpty() &&
     * !publicKey.getAlgorithm().equals(privateKey.getAlgorithm())) { throw new
     * WebApplicationException("Public and Private Key Algorithm mismatch!"); }
     * 
     * 
     * // Get keyStore details AppConfiguration appConfiguration =
     * this.getAppConfiguration(); String keyStoreFile =
     * appConfiguration.getKeyStoreFile(); String keyStoreSecret =
     * appConfiguration.getKeyStoreSecret();
     * log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " +
     * keyStoreFile + " , keyStoreSecret = " + keyStoreSecret);
     * 
     * // For testing - TBD - Start keyStoreFile =
     * "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
     * // For testing - TBD - End
     * 
     * // Get CryptoProvider AuthCryptoProvider cryptoProvider = new
     * AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " +
     * cryptoProvider);
     * 
     * // Get keys
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" +
     * cryptoProvider.getKeys());
     * 
     * //Generate JWK JSONWebKeySet jwks = this.generateKeys(cryptoProvider,
     * publicKey.getAlgorithm(),publicKey.getAlgorithm());
     * 
     * //import cryptoProvider.getKeyStore().setKeyEntry(alias, publicKey,
     * keyStoreSecret.toCharArray(), null);
     * 
     * 
     * // Verify if key successfully imported boolean keyExistsInStore =
     * cryptoProvider.getKeyStore().containsAlias(alias);
     * 
     * //Update Jwks
     * 
     * 
     * log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" +
     * keyExistsInStore); } catch (Exception exp) { exp.printStackTrace();
     * log.error("Failed to import key", exp); throw new
     * WebApplicationException("Error while importing key - " + exp); }
     * 
     * }
     */

    private byte[] parseDERFromPEM(String data, String beginDelimiter, String endDelimiter) {
        log.debug("\n\n KeyStoreService::parseDERFromPEM() - data =" + data + " , beginDelimiter = " + beginDelimiter
                + " , endDelimiter = " + endDelimiter);

        if (data != null && data.contains(beginDelimiter) && data.contains(endDelimiter)) {
            String[] tokens = data.split(beginDelimiter);
            tokens = tokens[1].split(endDelimiter);
            return (Base64.decode(tokens[0]));
        }
        return null;
    }

    private PublicKey generatePublicKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    private PrivateKey generatePrivateKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    /*
      public void importKey2(ClientCertificate clientCertificate) throws Exception {
      try { 
          log.debug("\n\n KeyStoreService::importKey() - clientCertificate = " +
      clientCertificate);
      
      // Validate cert validateClientCertificate(clientCertificate);
      
      // Get cert CertificateFactory fact =
      CertificateFactory.getInstance("X.509");
      X509Certificate cert = this.x509CertificateFromPem(clientCertificate.getCert());
      log.debug("\n\n KeyStoreService::importKey() - cert =" + cert);
      
      // Get Key chain
      X509Certificate[] certChain = new X509Certificate[1];
      certChain[0] = cert;
      log.debug("\n\n KeyStoreService::importKey() - certChain = " + certChain);
      
      // Get Public Key 
      PublicKey publicKey = cert.getPublicKey(); 
      byte[]  encodedKey = publicKey.getEncoded();
      log.debug("\n\n KeyStoreService::importKey() - publicKey =" + publicKey +
      " , publicKey.getAlgorithm() = " + publicKey.getAlgorithm() +
      " , publicKey.getFormat() = " + publicKey.getFormat() + " , encodedKey = " +
      encodedKey);
      
      // Get Private 
      Key byte[] encoded = getKeyFromPem(clientCertificate.getPrivateKey()); 
      KeyFactory keyFactory = KeyFactory.getInstance(publicKey.getAlgorithm()); 
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded); 
      PrivateKey key = keyFactory.generatePrivate(keySpec);
      log.debug("\n\n KeyStoreService::importKey() - key =" + key.getEncoded());
      
      
      // import key // Get keyStore details 
      AppConfiguration appConfiguration = this.getAppConfiguration(); String keyStoreFile =
      appConfiguration.getKeyStoreFile(); 
      String keyStoreSecret = appConfiguration.getKeyStoreSecret();
      log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " + keyStoreFile + " , keyStoreSecret = " + keyStoreSecret);
      
      // For testing - TBD - Start keyStoreFile =
      "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
      // For testing - TBD - End
      
      // Get CryptoProvider AuthCryptoProvider cryptoProvider = new
      AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
      log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " +cryptoProvider);
      
      // Get keys
      log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" + cryptoProvider.getKeys());
      
      cryptoProvider.getKeyStore().setKeyEntry(clientCertificate.getAlias(),
      publicKey, keyStoreSecret.toCharArray(), certChain);
      
      // Generate Jwks // 
      //this.generateKeys(cryptoProvider, List<Algorithm> signatureAlgorithms, List<Algorithm> encryptionAlgorithms, int expiration,nt expirationHours)
      
      // Verify if key successfully imported boolean keyExistsInStore =
      cryptoProvider.getKeyStore().containsAlias(clientCertificate.getAlias());
      log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" +
      keyExistsInStore); } catch (Exception exp) { exp.printStackTrace();
      log.error("Failed to import key", exp); throw new
      WebApplicationException("Error while importing key - " + exp); }
      
      }
     */

    /*
     * 
     * public void importKey(ClientCertificate clientCertificate) throws Exception {
     * try { log.debug("\n\n KeyStoreService::importKey() - clientCertificate = "
     * +clientCertificate); String format = clientCertificate.getFormat(); String
     * certContent = clientCertificate.getContent();
     * 
     * log.debug("\n\n KeyStoreService::importKey() - format = " + format
     * +" , certContent = " + certContent); if (format == null || certContent ==
     * null) { throw new WebApplicationException(" CERT PEM is null! "); }
     * 
     * //For testing - TBD - Start certContent = CERT_PEM_1;
     * log.debug("\n\n KeyStoreService::importKey() - CERT_PEM_1 format  = " +
     * format +" , certContent = " + certContent); //For testing - TBD - End -
     * 
     * // Get keyStore details AppConfiguration appConfiguration =
     * this.getAppConfiguration(); String keyStoreFile =
     * appConfiguration.getKeyStoreFile(); String keyStoreSecret =
     * appConfiguration.getKeyStoreSecret();
     * log.debug("\n\n KeyStoreService::importKey() - keyStoreFile = " +
     * keyStoreFile + " , keyStoreSecret = " + keyStoreSecret);
     * 
     * // For testing - TBD - Start keyStoreFile =
     * "D:\\1.PUJA\\8.PUJA_WORK_EXP\\3.COMPANY\\9.GLUU\\4.SERVER_FILES\\pujavs.jans.server2\\opt\\gluu-server\\etc\\certs\\jans-auth-keys.jks";
     * // For testing - TBD - End
     * 
     * // Get CryptoProvider AuthCryptoProvider cryptoProvider = new
     * AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider = " +
     * cryptoProvider);
     * 
     * // Get keys
     * log.debug("\n\n KeyStoreService::importKey() - cryptoProvider.getKeys() =" +
     * cryptoProvider.getKeys());
     * 
     * //Get cert CertificateFactory fact = CertificateFactory.getInstance("X.509");
     * X509Certificate cert = this.x509CertificateFromPem(certContent);
     * log.debug("\n\n KeyStoreService::importKey() - cert =" + cert);
     * 
     * 
     * //Get Key chain //X509Certificate[] certChain =
     * this.getX509CertificateChain(publicKey, dnName, this.getKeyExpirationTime(),
     * // cryptoProvider); X509Certificate[] certChain = new X509Certificate[1];
     * certChain[0] = cert;
     * log.debug("\n\n KeyStoreService::importKey() - certChain = "+certChain);
     * 
     * 
     * 
     * //Get Public Key PublicKey publicKey = cert.getPublicKey(); byte[] encodedKey
     * = publicKey.getEncoded();
     * log.debug("\n\n KeyStoreService::importKey() - publicKey =" + publicKey
     * +" , publicKey.getAlgorithm() = "+publicKey.getAlgorithm()
     * +" , publicKey.getFormat() = "+publicKey.getFormat()
     * +" , encodedKey = "+encodedKey);
     * 
     * 
     * 
     * // Generate Kid String alias = UUID.randomUUID().toString() +
     * getKidSuffix(Use.SIGNATURE.getParamName(), publicKey.getAlgorithm());
     * log.debug("\n\n KeyStoreService::importKey() - alias = " + alias);
     * 
     * // import key cryptoProvider.getKeyStore().setKeyEntry(alias, publicKey,
     * keyStoreSecret.toCharArray(), certChain);
     * 
     * //Generate Jwks // this.generateKeys(cryptoProvider, List<Algorithm>
     * signatureAlgorithms, // List<Algorithm> encryptionAlgorithms, int expiration,
     * int expirationHours)
     * 
     * // Verify if key successfully imported boolean keyExistsInStore =
     * cryptoProvider.getKeyStore().containsAlias(alias);
     * log.debug("\n\n KeyStoreService::importKey() - keyExistsInStore 3 =" +
     * keyExistsInStore); } catch (Exception exp) { exp.printStackTrace();
     * log.error("Failed to import key", exp); throw new
     * WebApplicationException("Error while importing key - " + exp); }
     * 
     * }
     */

    /*
     * private void generateKeys(PublicKey publicKey ,X509Certificate cert,
     * X509Certificate[] certChain) throws Exception, JSONException {
     * 
     * log.
     * debug("\n\n KeyStoreService::generateKeys() - publicKey: {}, cert: {}, certChain:{}"
     * , publicKey, cert, certChain);
     * 
     * //Generate Key set JSONWebKeySet jwks = new JSONWebKeySet();
     * 
     * Calendar calendar = new GregorianCalendar(); calendar.add(Calendar.DATE,
     * expiration); calendar.add(Calendar.HOUR, expirationHours);
     * 
     * Algorithm algorithm = Algorithm.fromString(publicKey.getAlgorithm());
     * 
     * SignatureAlgorithm signatureAlgorithm =
     * SignatureAlgorithm.fromString(algorithm.name()); JSONObject result =
     * cryptoProvider.generateKey(algorithm, calendar.getTimeInMillis(),
     * Use.SIGNATURE);
     * 
     * JSONWebKey key = new JSONWebKey(); key.setKid(result.getString(KEY_ID));s
     * key.setUse(Use.SIGNATURE); key.setAlg(algorithm);
     * key.setKty(KeyType.fromString(signatureAlgorithm.getFamily().toString()));
     * key.setExp(result.optLong(EXPIRATION_TIME));
     * key.setCrv(signatureAlgorithm.getCurve());
     * key.setN(result.optString(MODULUS)); key.setE(result.optString(EXPONENT));
     * key.setX(result.optString(X)); key.setY(result.optString(Y));
     * 
     * JSONArray x5c = result.optJSONArray(CERTIFICATE_CHAIN);
     * key.setX5c(io.jans.as.model.util.StringUtils.toList(x5c));
     * 
     * jwks.getKeys().add(key);
     * 
     * }
     */
    
    private JSONWebKey generateSigningKey(AbstractCryptoProvider cryptoProvider, String strSignatureAlgorithm) throws Exception, JSONException {
        log.debug("\n\n KeyStoreService::generateSigningKey() - cryptoProvider: {}, strSignatureAlgorithm: {}",cryptoProvider, strSignatureAlgorithm);
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

        //TBD for testing - Start ???
        strEncryptionAlgorithm = "RSA1_5";
        //TBD for testing - End ???
        
        algorithm = Algorithm.fromString(strEncryptionAlgorithm);
        log.debug("\n\n KeyStoreService::generateKeys() - algorithm = " + algorithm);
        KeyEncryptionAlgorithm encryptionAlgorithm = KeyEncryptionAlgorithm.fromName(algorithm.getParamName());
        //log.debug("\n\n KeyStoreService::generateKeys() - encryptionAlgorithm = " + encryptionAlgorithm);
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
     * //cryptoProvider.keyStore.setKeyEntry(alias, pk,keyStoreSecret.toCharArray(),
     * chain); cryptoProvider.getKeyStore().setCertificateEntry(alias, cert);
     * log.debug("\n\n KeyStoreService::importKey() - Certificate loaded");
     * 
     * //cryptoProvider.getKeyStore().setKeyEntry(alias, cert.getSignature(),chain);
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

    public byte[] getKeyFromPem(String pem) {
        pem = StringUtils.remove(pem, "-----BEGIN PRIVATE KEY-----");
        pem = StringUtils.remove(pem, "-----END PRIVATE KEY-----");
        return (Base64.decode(pem));
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
    /*
     * public KeyPair getPrivateKey(String strAlgorithm) throws Exception {
     * 
     * Algorithm algorithm = Algorithm.fromString(strAlgorithm);
     * 
     * log.debug("\n\n KeyStoreService::generateKey() - algorithm = " + algorithm);
     * 
     * KeyPairGenerator keyGen = null; SignatureAlgorithm signatureAlgorithm =
     * SignatureAlgorithm.fromString(algorithm.getParamName());
     * 
     * log.debug("\n\n KeyStoreService::getPrivateKey() - algorithm = " + algorithm
     * + " , signatureAlgorithm = " + signatureAlgorithm); if (algorithm == null) {
     * throw new
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
     * // Generate the key KeyPair keyPair = keyGen.generateKeyPair();
     * 
     * log.debug("\n\n KeyStoreService::getPrivateKey() - keyPair = " + keyPair);
     * return keyPair;
     * 
     * }
     */

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
