/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.blazartech.products.blazarusermanagement.tokenutil;

import com.blazartech.products.crypto.BlazarCryptoFile;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * provide the utilities. See https://dzone.com/articles/spring-boot-security-json-web-tokenjwt-hello-world
 * @author AAR1069
 */
@Component
public class JwtTokenUtilImpl implements JwtTokenUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtilImpl.class);

    @Value("${blazartech.jwt.expiry:0}")
    public long tokenExpiry;

    @Value("${blazartech.user.management.service.secret.userID}")
    private String secretUserID;

    @Value("${blazartech.user.management.service.secret.resourceID}")
    private String secretResourceID;

    @Autowired
    private BlazarCryptoFile cryptoFile;

    private static final SecretKey SECRET_KEY = Jwts.SIG.HS512.key().build();
    
    private SecretKey signingKey() {
        return SECRET_KEY;
    }
    
    private String getSecret() {
        return cryptoFile.getPassword(secretUserID, secretResourceID);
    }

    //retrieve username from jwt token
    @Override
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    @Override
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    @Override
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        Jws<Claims> claims = Jwts.parser().verifyWith(signingKey()).build().parseSignedClaims(token);
        return claims.getPayload();
//        return Jwts.parser().setSigningKey(getSecret()).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        logger.info("expiration date: " + expiration);
        return expiration.before(new Date());
    }

    //generate token for user
    @Override
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        String[] authorities = new String[userDetails.getAuthorities().size()];
        userDetails.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.toList())
                .toArray(authorities);
        claims.put("roles", authorities);
        return doGenerateToken(claims, userDetails.getUsername());
    }
    
    @Override
    public Collection<String> getRoles(String token) {
        Claims claims = getAllClaimsFromToken(token);
        List<String> roles = claims.get("roles", List.class);
        return roles;
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string 
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + tokenExpiry * 1000))
                .signWith(signingKey())
                .compact();
    }

    //validate token
    @Override
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    
    private static final String BEARER_HEADER = "Bearer ";
    
    @Override
    public String getToken(HttpServletRequest request) {
        final String requestTokenHeader = request.getHeader("Authorization");

        String jwtToken = null;

        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith(BEARER_HEADER)) {
            jwtToken = requestTokenHeader.substring(BEARER_HEADER.length());
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }
        
        return jwtToken;
    }
}
