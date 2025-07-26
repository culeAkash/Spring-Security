package com.spring.security.SpringSecurityLearn.services;


import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import com.spring.security.SpringSecurityLearn.models.JwtUserDetails;
import com.spring.security.SpringSecurityLearn.repositories.BasicUserDetailsRepository;
import com.spring.security.SpringSecurityLearn.repositories.JwtUserDetailsRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// implemented UserDetailsService as its loadUserByUsername() will be called to get user details during authentication
@Service
public class JwtUserDetailsService implements UserDetailsService {
    private final JwtUserDetailsRepository userDetailsRepository;

    public JwtUserDetailsService(JwtUserDetailsRepository userDetailsRepository){
        this.userDetailsRepository = userDetailsRepository;
    }

    public JwtUserDetails register(JwtUserDetails userDetails){
        return this.userDetailsRepository.save(userDetails);
    }

    @Override
    public JwtUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userDetailsRepository.findByUsername(username)
                .orElseThrow(() ->new UsernameNotFoundException("Not found"));
    }
}
