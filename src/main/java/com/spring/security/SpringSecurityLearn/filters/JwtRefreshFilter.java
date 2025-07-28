package com.spring.security.SpringSecurityLearn.filters;

import com.spring.security.SpringSecurityLearn.models.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtRefreshFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;


    public JwtRefreshFilter(AuthenticationManager authenticationManager,JwtUtil jwtUtil){
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }



    // filter for refresh token validation and new token creation
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(!request.getServletPath().equals("/refresh-token")){
            filterChain.doFilter(request,response);
            return;
        }

        String refreshToken = extractJwtFromRequest(request);

        if(refreshToken==null){
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // The refresh token is validated in the same way as Normal token
        JwtValidationToken validationToken = new JwtValidationToken(refreshToken);
        Authentication authentication = authenticationManager.authenticate(validationToken);

        // if valid refresh token create new JWT tOken and set in header
        if(authentication.isAuthenticated()){
            String newToken = jwtUtil.generateToken(authentication.getName(),15);
            response.setHeader("Authorization","Bearer " + newToken);
        }
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if(cookies == null || cookies.length==0){
            return null;
        }

        String refreshToken = null;
        for(Cookie cookie : cookies){
            if("refreshToken".equals(cookie.getName())){
                refreshToken = cookie.getValue();
            }
        }
        return refreshToken;
    }
}
