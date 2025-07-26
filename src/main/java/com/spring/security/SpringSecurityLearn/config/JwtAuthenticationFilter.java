package com.spring.security.SpringSecurityLearn.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.SpringSecurityLearn.models.JwtUtil;
import com.spring.security.SpringSecurityLearn.payloads.LoginRequest;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil; // to create JWT Token based on username


    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,JwtUtil jwtUtil){
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // If the request is not for generating token then move on to the next filter
        if(!request.getServletPath().equals("/generate_token")){
            filterChain.doFilter(request,response);
            return;
        }

        // Create Login Request object from request object
        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);


        // Generate Authentication Token to be passed to the Authentication Manager
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
            loginRequest.getUsername(),loginRequest.getPassword()
        );


        //Send the Authentication token to the authmanager to authenticate
        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        // If authenticated then create JWT Token from the JWT Util object
        if(authentication.isAuthenticated()){
            String token = jwtUtil.generateToken(authentication.getName(),30);
            LOGGER.info("JWT Token : {}" , token);
            // attach the token to the response
            response.addHeader("Authorization","Bearer " + token);
        }

    }
}
