package com.spring.security.SpringSecurityLearn.services;

import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import com.spring.security.SpringSecurityLearn.repositories.BasicUserDetailsRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// implemented UserDetailsService as its loadUserByUsername() will be called to get user details during authentication
@Service
public class BasicUserDetailsService implements UserDetailsService {


    private final BasicUserDetailsRepository userDetailsRepository;

    public BasicUserDetailsService(BasicUserDetailsRepository userDetailsRepository){
        this.userDetailsRepository = userDetailsRepository;
    }

    public BasicUserDetails register(BasicUserDetails basicUserDetails){
        return this.userDetailsRepository.save(basicUserDetails);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userDetailsRepository.findByUsername(username)
                .orElseThrow(() ->new UsernameNotFoundException("Not found"));
    }
}
