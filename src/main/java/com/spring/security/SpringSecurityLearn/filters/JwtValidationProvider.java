package com.spring.security.SpringSecurityLearn.filters;

import com.spring.security.SpringSecurityLearn.models.JwtUserDetails;
import com.spring.security.SpringSecurityLearn.models.JwtUtil;
import com.spring.security.SpringSecurityLearn.services.JwtUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

// We have created a new type of token, so in order to handle that we need a new AuthenticationProvider and need to add it to AuthManager list
public class JwtValidationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;
    private final JwtUserDetailsService userDetailsService;


    private static final Logger LOGGER = LoggerFactory.getLogger(JwtValidationProvider.class);

    public JwtValidationProvider(JwtUtil jwtUtil,JwtUserDetailsService userDetailsService){
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Get token from Token object
        String token = ((JwtValidationToken) authentication).getToken();

        String username = jwtUtil.validateAndExtractUsername(token);

        LOGGER.info(username);

        if(username==null){
            throw new BadCredentialsException("Invalid JWT Token");
        }

        JwtUserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // return new authtoken with isAuthenticated set as true, we can also send the JwtValidationToken by adding extra fields to it
        return new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtValidationToken.class.isAssignableFrom(authentication));
    }
}
