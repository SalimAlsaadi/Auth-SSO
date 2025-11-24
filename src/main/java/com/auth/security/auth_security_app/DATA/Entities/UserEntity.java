package com.auth.security.auth_security_app.DATA.Entities;

import com.auth.security.auth_security_app.admin.entity.RoleEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
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

    @Column(name = "ref_id")
    private Long refId;

    @Column(name = "ref_type", length = 20)
    private String refType;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_allowed_clients",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "client_id", length = 100)
    private Set<String> allowedClientIds = new HashSet<>();

    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "sas_user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<RoleEntity> roles = new HashSet<>();
}
