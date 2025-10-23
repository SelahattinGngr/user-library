package com.selahattindev.userlibrary.utils;

public enum KeyAlgorithm {
    RSA_512("RSA", 512, KeyType.ASYMMETRIC),
    RSA_1024("RSA", 1024, KeyType.ASYMMETRIC),
    RSA_2048("RSA", 2048, KeyType.ASYMMETRIC),
    HMAC_SHA256("HmacSHA256", 256, KeyType.SYMMETRIC),
    HMAC_SHA512("HmacSHA512", 512, KeyType.SYMMETRIC);

    private final String algorithm;
    private final int bitLength;
    private final KeyType keyType;

    KeyAlgorithm(String algorithm, int bitLength, KeyType keyType) {
        this.algorithm = algorithm;
        this.bitLength = bitLength;
        this.keyType = keyType;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getBitLength() {
        return bitLength;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public enum KeyType {
        ASYMMETRIC, SYMMETRIC
    }
}
