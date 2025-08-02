package com.spring.security.SpringSecurityLearn.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2Controller {

    @GetMapping("/")
    public String defaultHomePageMethod(){
        return "Hello, You are logged in";
    }

    @GetMapping("/users")
    public String getUserDetails(){
        return "fetched the details successfully";
    }
}
