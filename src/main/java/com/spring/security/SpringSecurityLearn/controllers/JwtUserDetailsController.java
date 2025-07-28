package com.spring.security.SpringSecurityLearn.controllers;


import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import com.spring.security.SpringSecurityLearn.models.JwtUserDetails;
import com.spring.security.SpringSecurityLearn.services.BasicUserDetailsService;
import com.spring.security.SpringSecurityLearn.services.JwtUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/v1/jwt/auth")
public class JwtUserDetailsController {
    private final JwtUserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    public JwtUserDetailsController(JwtUserDetailsService userDetailsService,PasswordEncoder passwordEncoder){
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<JwtUserDetails> register(@RequestBody JwtUserDetails userDetails){
        userDetails.setPassword(this.passwordEncoder.encode(userDetails.getPassword()));

        JwtUserDetails newUserDetails = this.userDetailsService.register(userDetails);

        return ResponseEntity.accepted().body(newUserDetails);
    }

    @GetMapping("/users")
    public ResponseEntity<String> getUser(){
        return ResponseEntity.ok("Fetched User Details Successfully");
    }
}
