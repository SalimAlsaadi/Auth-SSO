package com.auth.security.auth_security_app.DATA.Entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

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

    @Column(name="clientId")
    private List<String> allowedClientIds; // e.g., ["frontend-client", "admin-dashboard"]

}
