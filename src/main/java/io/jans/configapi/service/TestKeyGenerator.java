package io.jans.configapi.service;

import java.security.Key;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import io.jans.as.model.crypto.signature.AlgorithmFamily;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Algorithm;

import org.slf4j.Logger;

@ApplicationScoped
public class TestKeyGenerator {

    @Inject
    Logger log;

    public PublicKey getPublicKey() throws Exception {
        KeyPair keyPair = getKeyPair("RS256");
        log.debug("\n\n TestKeyGenerator::getPublicKey() - keyPair = " + keyPair);
        PublicKey key = keyPair.getPublic();
        log.debug("\n\n TestKeyGenerator::getPublicKey() - key = " + key);
        return key;

    }

    private KeyPair getKeyPair(String strAlgorithm) throws Exception {
        log.debug("\n\n TestKeyGenerator::getKeyPair() - strAlgorithm = " + strAlgorithm);

        Algorithm algorithm = Algorithm.fromString(strAlgorithm);
        log.debug("\n\n TestKeyGenerator::getKeyPair() - algorithm = " + algorithm.getParamName());

        KeyPairGenerator keyGen = null;
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(algorithm.getParamName());

        log.debug("\n\n TestKeyGenerator::getKeyPair() - algorithm = " + algorithm + " , signatureAlgorithm = "
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

        log.debug("\n\n TestKeyGenerator::getKeyPair() - keyPair = " + keyPair);
        return keyPair;

    }
}
