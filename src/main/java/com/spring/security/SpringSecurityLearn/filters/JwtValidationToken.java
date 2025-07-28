package com.spring.security.SpringSecurityLearn.filters;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class JwtValidationToken extends AbstractAuthenticationToken {

    private final String token;


    public JwtValidationToken(String token){
        super(null);
        this.token = token;
        // setting the Authenticated as false as it must be validated by AuthProvider
        setAuthenticated(false);
    }

    public String getToken(){
        return this.token;
    }


    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
