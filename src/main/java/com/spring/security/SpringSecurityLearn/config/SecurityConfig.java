package com.spring.security.SpringSecurityLearn.config;


import com.spring.security.SpringSecurityLearn.filters.JwtAuthenticationFilter;
import com.spring.security.SpringSecurityLearn.filters.JwtRefreshFilter;
import com.spring.security.SpringSecurityLearn.filters.JwtValidationFilter;
import com.spring.security.SpringSecurityLearn.filters.JwtValidationProvider;
import com.spring.security.SpringSecurityLearn.models.JwtUtil;
import com.spring.security.SpringSecurityLearn.services.JwtUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)// for PreAuthorize and PostAuthorize to work
public class SecurityConfig {


    private final JwtUtil jwtUtil;
    private final JwtUserDetailsService userDetailsService;


    public SecurityConfig(JwtUtil jwtUtil,JwtUserDetailsService userDetailsService){
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }


    // Specify the Password Encoder to be used by Authentication Provider
    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


    // We have to do all this manually as we are not using internal spring functionality
    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
         DaoAuthenticationProvider authenticationProvider =new DaoAuthenticationProvider(
                userDetailsService
        );
         authenticationProvider.setPasswordEncoder(getPasswordEncoder());
         return authenticationProvider;
    }


    @Bean
    public JwtValidationProvider jwtValidationProvider(){
        return new JwtValidationProvider(jwtUtil,userDetailsService);
    }


//    @Bean
//    public SecurityFilterChain securityFilterChain1(HttpSecurity httpSecurity) throws Exception {
//
//        // For JWT auth
//        // Create the object of Auth Filter
//        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(getAuthenticationManager(),jwtUtil);
//
//        // Create object for validation filter
//        JwtValidationFilter jwtValidationFilter = new JwtValidationFilter(getAuthenticationManager());
//
//        // Create JWT Refresh filter
//        JwtRefreshFilter jwtRefreshFilter = new JwtRefreshFilter(getAuthenticationManager(),jwtUtil);
//
//        httpSecurity
//                .securityMatcher("/api/v1/jwt/**")
//                .authorizeHttpRequests(auth ->
//                        auth.requestMatchers("/api/v1/jwt/auth/register").permitAll()
//                                .anyRequest().authenticated()
//                )
//                .sessionManagement(session->session.sessionCreationPolicy(
//                        SessionCreationPolicy.STATELESS
//                ))
//                .csrf(csrf -> csrf.disable())
//                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)// Add the filter to the security filter chain
//                .addFilterAfter(jwtValidationFilter, JwtAuthenticationFilter.class)// add the filter for validation
//                .addFilterAfter(jwtRefreshFilter, JwtValidationFilter.class);
//        return httpSecurity.build();
//    }



    // Security Filter Chain for role based authorization demo
    @Bean
    public SecurityFilterChain securityFilterChain3(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .securityMatcher("/api/v1/auth/role")
                .authorizeHttpRequests(auth->
                        auth.requestMatchers("/api/v1/auth/role/login-user").permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement(session->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(csrf->csrf.disable())
                .httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }



    // For OAuth2 authentication
//    @Bean
//    public SecurityFilterChain securityFilterChain2(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.authorizeHttpRequests(auth->auth
//                        .requestMatchers("/login/**","/oauth2/**").permitAll()
//                        .anyRequest().authenticated()
//        )
//                .csrf(csrf -> csrf.disable())
//                .oauth2Login(Customizer.withDefaults());
//        return httpSecurity.build();
//    }





    // new auth managers are always empty and we have to pass provider to it
    @Bean
    public AuthenticationManager getAuthenticationManager(){
        return new ProviderManager(
                Arrays.asList(
                        authenticationProvider(),
                        jwtValidationProvider()
                )
        );
    }


    // Now create custom InMemoryUserDetailsManager object to use
//    @Bean
//    public UserDetailsService getInMemoryUserDetailsManager(){
//        UserDetails user1 = User.builder()
//                .username("culeAkash1")
//                .password(getPasswordEncoder().encode("Ajju123"))
//                .build();
//
//        UserDetails user2 = User.builder()
//                .username("culeAkash2")
//                .password(getPasswordEncoder().encode("Ajju123"))
//                .build();
//
//        return new InMemoryUserDetailsManager(user1,user2);
//    }
}
