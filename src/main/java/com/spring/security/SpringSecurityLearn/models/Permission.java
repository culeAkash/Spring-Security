package com.spring.security.SpringSecurityLearn.models;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "user_permission")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    private String name; // e.g. ORDER_READ, SALES_READ
}
