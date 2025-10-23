package com.selahattindev.userlibrary.service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.selahattindev.userlibrary.config.JwtProperties;
import com.selahattindev.userlibrary.utils.KeyAlgorithm;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final JwtProperties jwtProperties;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    /*
     * Create Access Token
     */

    public String generateAccessToken(String subject, Long expirationMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMillis);

        if (jwtProperties.getAlgorithm().getKeyType() == KeyAlgorithm.KeyType.ASYMMETRIC) {
            KeyPair keyPair = jwtProperties.getKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            return Jwts.builder()
                    .subject(subject)
                    .expiration(expiryDate)
                    .signWith(privateKey)
                    .compact();
        } else {
            SecretKey secretKey = Keys.hmacShaKeyFor(jwtProperties.getAccessSecret().getBytes());

            return Jwts.builder()
                    .subject(subject)
                    .expiration(expiryDate)
                    .signWith(secretKey)
                    .compact();
        }
    }

    /*
     * Create Refresh Token
     */

    public String generateRefreshToken(String subject, Long expirationMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMillis);

        if (jwtProperties.getAlgorithm().getKeyType() == KeyAlgorithm.KeyType.ASYMMETRIC) {
            KeyPair keyPair = jwtProperties.getKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            return Jwts.builder()
                    .subject(subject)
                    .expiration(expiryDate)
                    .signWith(privateKey)
                    .compact();
        } else {
            SecretKey secretKey = Keys.hmacShaKeyFor(jwtProperties.getRefreshSecret().getBytes());

            return Jwts.builder()
                    .subject(subject)
                    .expiration(expiryDate)
                    .signWith(secretKey)
                    .compact();
        }
    }

    /*
     * Validate Token
     */

    public Jwt<?, ?> parseToken(String token) {
        if (jwtProperties.getAlgorithm().getKeyType() == KeyAlgorithm.KeyType.ASYMMETRIC) {
            PublicKey publicKey = jwtProperties.getKeyPair().getPublic();

            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parse(token);
        } else {
            SecretKey secretKey = Keys.hmacShaKeyFor(jwtProperties.getAccessSecret().getBytes());
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parse(token);
        }
    }
}
