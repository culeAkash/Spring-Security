package com.spring.security.SpringSecurityLearn.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Specify the Password Encoder to be used by Authentication Provider
    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/v1/auth/register").permitAll()
                                .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
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
