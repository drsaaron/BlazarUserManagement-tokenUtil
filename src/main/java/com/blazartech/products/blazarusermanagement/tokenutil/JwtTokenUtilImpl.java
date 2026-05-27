/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.blazartech.products.blazarusermanagement.tokenutil;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * provide the utilities. See https://dzone.com/articles/spring-boot-security-json-web-tokenjwt-hello-world
 * 
 * This implementation will use asymmetric encryption to sign the token.  In te real
 * world this would necessitate breaking up this component into two: one for creating
 * the tokens, which would use the private key to sign, and one to read the token, which would
 * use the public key to validate.  Including both keys in this jar rather defeats the
 * whole purpose of signing.  But this isn't the real world, just something running on my
 * laptop, and illustrates how to do things in the real world.  So it's good enough.
 * 
 * @author AAR1069
 */
@Component
public class JwtTokenUtilImpl implements JwtTokenUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtilImpl.class);

    @Value("${blazartech.jwt.expiry:0}")
    public long tokenExpiry;
    
    @Autowired
    private PublicPrivateKeyHolder keyHolder;

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
        return Jwts.parser()
                .verifyWith(keyHolder.getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
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
                .signWith(keyHolder.getPrivateKey(), Jwts.SIG.RS256)
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
