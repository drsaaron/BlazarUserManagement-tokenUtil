/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.blazartech.products.blazarusermanagement.tokenutil;

import com.blazartech.products.crypto.BlazarCryptoFile;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 *
 * @author AAR1069
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {
    JwtTokenUtilImplTest.JwtTokenUtilImplTestConfiguration.class
})
public class JwtTokenUtilImplTest {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtilImplTest.class);
    
    @Configuration
    @PropertySource("classpath:test.properties")
    static class JwtTokenUtilImplTestConfiguration {
        
        @Bean
        public JwtTokenUtilImpl instance() {
            return new JwtTokenUtilImpl();
        }
    }
    
    @Autowired
    private JwtTokenUtilImpl instance;
    
    @MockBean
    private BlazarCryptoFile cryptoFile;
    
    public JwtTokenUtilImplTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
        Mockito.when(cryptoFile.getPassword(Mockito.any(), Mockito.any()))
                .thenReturn("myResource");
    }
    
    @AfterEach
    public void tearDown() {
    }

    private static final String MOCK_TOKEN = "MOCKABCDEF157";
    
    /**
     * Test of getToken method, of class JwtTokenUtilImpl.
     */
    @Test
    public void testGetToken() {
        logger.info("getToken");
        
        SimpleHttpServletRequest request = new SimpleHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + MOCK_TOKEN);
        
        String expResult = MOCK_TOKEN;
        String result = instance.getToken(request);
        assertEquals(expResult, result);
    }
    
    @Test
    public void testGetToken_noAuthorization() {
        logger.info("getToken_noAuthorization");
        
        SimpleHttpServletRequest request = new SimpleHttpServletRequest();
        
        String result = instance.getToken(request);
        assertNull(result);
    }
    
    @Test
    public void testGetToken_badHeader() {
        logger.info("getToken_badHeader");
        
        SimpleHttpServletRequest request = new SimpleHttpServletRequest();
        request.addHeader("Authorization", MOCK_TOKEN);
        
        String result = instance.getToken(request);
        assertNull(result);
    }
    
    static class MyAuthority implements GrantedAuthority {

        private final String authority;

        public MyAuthority(String authority) {
            this.authority = authority;
        }
        
        
        @Override
        public String getAuthority() {
            return authority;
        }
        
    }
    
    private static final String ROLE1 = "Auth1";
    private static final String ROLE2 = "Auth2";
    
    @Test
    public void testGetRoles() {
        logger.info("getRoles");
        
        Collection<GrantedAuthority> authorities = List.of(new MyAuthority(ROLE1), new MyAuthority(ROLE2));
        UserDetails details = new User("testUser", "testPass", authorities);
        String token = instance.generateToken(details);
        Collection<String> roles = instance.getRoles(token);
        
        assertEquals(2, roles.size());
        
        String firstRole = roles.iterator().next();
        assertEquals(ROLE1, firstRole);
    }
}
