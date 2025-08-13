package com.auth.security.auth_security_app.DATA.Entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(nullable = false, length = 255)
    private String password;

    @Column(nullable = false, length = 50)
    private String role;

    // Refers to Landlord or Tenant ID from main app
    @Column(name = "ref_id")
    private Long refId;

    @Column(name = "ref_type", length = 20)
    private String refType; // LANDLORD or TENANT


    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_allowed_clients", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "client_id", length = 100)
    private Set<String> allowedClientIds = new HashSet<>();

}
