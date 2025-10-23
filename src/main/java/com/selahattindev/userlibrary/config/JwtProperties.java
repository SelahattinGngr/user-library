package com.selahattindev.userlibrary.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.selahattindev.userlibrary.utils.KeyAlgorithm;

@ConfigurationProperties(prefix = "userlibrary.jwt")
public class JwtProperties {

    private KeyAlgorithm algorithm = KeyAlgorithm.RSA_2048;

    private String privateKey = "";
    private String publicKey = "";

    private String accessSecret = "";
    private String refreshSecret = "";

    private KeyPair keyPair;

    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(KeyAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String getPrivateKey() {
        ensureKeys();
        return privateKey;
    }

    public String getPublicKey() {
        ensureKeys();
        return publicKey;
    }

    public String getAccessSecret() {
        ensureKeys();
        return accessSecret;
    }

    public String getRefreshSecret() {
        ensureKeys();
        return refreshSecret;
    }

    public KeyPair getKeyPair() {
        ensureKeys();
        return keyPair;
    }

    private synchronized void ensureKeys() {
        if (algorithm.getKeyType() == KeyAlgorithm.KeyType.ASYMMETRIC) {
            ensureAsymmetricKeys();
        } else {
            ensureSymmetricKeys();
        }
    }

    private void ensureAsymmetricKeys() {
        if (isEmpty(privateKey) || isEmpty(publicKey)) {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm.getAlgorithm());
                keyGen.initialize(algorithm.getBitLength());
                keyPair = keyGen.generateKeyPair();

                privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
                publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Asymmetric key generation failed", e);
            }
        }
    }

    private void ensureSymmetricKeys() {
        if (isEmpty(accessSecret) || isEmpty(refreshSecret)) {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance(algorithm.getAlgorithm());
                keyGen.init(algorithm.getBitLength());
                SecretKey accessKey = keyGen.generateKey();
                SecretKey refreshKey = keyGen.generateKey();

                accessSecret = Base64.getEncoder().encodeToString(accessKey.getEncoded());
                refreshSecret = Base64.getEncoder().encodeToString(refreshKey.getEncoded());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Symmetric key generation failed", e);
            }
        }
    }

    private boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }
}
