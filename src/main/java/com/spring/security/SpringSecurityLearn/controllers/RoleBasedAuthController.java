package com.spring.security.SpringSecurityLearn.controllers;


import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import com.spring.security.SpringSecurityLearn.payloads.LoginRequest;
import com.spring.security.SpringSecurityLearn.services.BasicUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/role")
public class RoleBasedAuthController {

    private final BasicUserDetailsService userDetailsService;


    private final PasswordEncoder passwordEncoder;

    public RoleBasedAuthController(BasicUserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }


    @PostMapping("login-user")
    public ResponseEntity<BasicUserDetails> loginUser(@RequestBody BasicUserDetails loginRequest){
        loginRequest.setPassword(this.passwordEncoder.encode(loginRequest.getPassword()));
        BasicUserDetails registered = userDetailsService.register(loginRequest);
        return ResponseEntity.ok(registered);
    }


    @GetMapping("/orders")
    @PreAuthorize("hasRole('USER') and hasAuthority('ORDER_READ')")
    public ResponseEntity<String> getOrders(){
        return ResponseEntity.ok("All Orders fetched successfully");
    }

    @GetMapping("/sales")
    @PreAuthorize("hasAuthority('ORDER_READ')")
    public ResponseEntity<String> getSales(){
        return ResponseEntity.ok("All Sales fetched successfully");
    }


}
