/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.blazartech.products.blazarusermanagement.tokenutil;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

/**
 *
 * @author scott
 */
@Component
public class PublicPrivateKeyHolderImpl implements PublicPrivateKeyHolder {

    private static final Logger logger = LoggerFactory.getLogger(PublicPrivateKeyHolderImpl.class);
    
    private final Resource privateKeyResource = new ClassPathResource("jwt-signing-private.pem");
    private final Resource publicKeyResource = new ClassPathResource("jwt-signing-public.pem");
    
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public PublicKey readPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String pemFile = new String(publicKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String publicKeyPem = pemFile
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\n", "");
        
        byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        return kf.generatePublic(spec);
    }
    
    public PrivateKey readPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String pemFile = new String(privateKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String privateKeyPem = pemFile
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\n", "");
        
        byte[] decoded = Base64.getDecoder().decode(privateKeyPem);
        
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        return kf.generatePrivate(spec);
    }
    
    @PostConstruct
    public void loadKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.info("loading keys");
        
        publicKey = readPublicKey();
        privateKey = readPrivateKey();
    }
}
