package com.auth.security.auth_security_app.admin.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "sas_permissions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PermissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer perm_id;  // INT → Integer

    @Column(nullable = false, unique = true, length = 100)
    private String permissionName;

    @Column(length = 200)
    private String description;

    @OneToMany(mappedBy = "permission", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<RolePermissionEntity> rolePermissions = new HashSet<>();
}
