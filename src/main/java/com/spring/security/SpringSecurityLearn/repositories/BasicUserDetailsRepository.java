package com.spring.security.SpringSecurityLearn.repositories;

import com.spring.security.SpringSecurityLearn.models.BasicUserDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BasicUserDetailsRepository extends JpaRepository<BasicUserDetails,Long> {

    public Optional<BasicUserDetails> findByUsername(String username);
}
