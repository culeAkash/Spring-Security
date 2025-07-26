package com.spring.security.SpringSecurityLearn.repositories;

import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import com.spring.security.SpringSecurityLearn.models.JwtUserDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JwtUserDetailsRepository extends JpaRepository<JwtUserDetails,Long> {
    public Optional<JwtUserDetails> findByUsername(String username);
}
