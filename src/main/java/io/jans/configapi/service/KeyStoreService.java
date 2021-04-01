package io.jans.configapi.service;

import com.google.common.base.Preconditions;
import io.jans.as.model.crypto.AbstractCryptoProvider;
import io.jans.as.model.crypto.AuthCryptoProvider;
import io.jans.as.model.crypto.encryption.KeyEncryptionAlgorithm;
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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;


@ApplicationScoped
public class KeyStoreService {

    private static String dnName = "CN=Jans Auth CA Certificates";

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

            // Get CryptoProvider
            AuthCryptoProvider cryptoProvider = new AuthCryptoProvider(keyStoreFile, keyStoreSecret, dnName);
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
        // This is giving error as neither cert or the public key has Encryption details????????????
        algorithm = Algorithm.fromString(strEncryptionAlgorithm);
        log.debug("\n\n KeyStoreService::generateKeys() - algorithm = " + algorithm);
        KeyEncryptionAlgorithm encryptionAlgorithm = KeyEncryptionAlgorithm.fromName(algorithm.getParamName());
        log.debug("\n\n KeyStoreService::generateKeys() - encryptionAlgorithm = " +
        encryptionAlgorithm);
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
