/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.blazartech.products.blazarusermanagement.tokenutil;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Date;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;

/**
 *
 * @author AAR1069
 */
public interface JwtTokenUtil {

    //generate token for user
    String generateToken(UserDetails userDetails);

    <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver);

    //retrieve expiration date from jwt token
    Date getExpirationDateFromToken(String token);

    //retrieve username from jwt token
    String getUsernameFromToken(String token);
    
    /** 
     * retrieve the roles from the jwt token
     * @param token the JWT token
     * @return the list of roles
     */
    Collection<String> getRoles(String token);

    //validate token
    Boolean validateToken(String token, UserDetails userDetails);
    
    /**
     * get the JWT token from a given request.
     * 
     * @param request the request
     * @return the token
     */
    String getToken(HttpServletRequest request);
}
