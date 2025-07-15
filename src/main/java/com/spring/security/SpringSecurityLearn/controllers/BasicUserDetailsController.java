package com.spring.security.SpringSecurityLearn.controllers;

import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import com.spring.security.SpringSecurityLearn.services.BasicUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/auth")
public class BasicUserDetailsController {

    private final BasicUserDetailsService basicUserDetailsService;

    private final PasswordEncoder passwordEncoder;

    public BasicUserDetailsController(BasicUserDetailsService basicUserDetailsService,PasswordEncoder passwordEncoder){
        this.basicUserDetailsService = basicUserDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<BasicUserDetails> register(@RequestBody BasicUserDetails basicUserDetails){
        basicUserDetails.setPassword(this.passwordEncoder.encode(basicUserDetails.getPassword()));

        BasicUserDetails userDetails = this.basicUserDetailsService.register(basicUserDetails);

        return ResponseEntity.accepted().body(userDetails);
    }
}
