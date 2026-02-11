package com.auth.security.auth_security_app.admin.entity;

import com.auth.security.auth_security_app.admin.superClassBaseEntity.BaseEntity;
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
public class PermissionEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "perm_id")
    private Integer perm_id;

    @Column(name = "permissionName", nullable = false, unique = true, length = 100)
    private String permissionName;

    @Column(name = "description", length = 200)
    private String description;

    @OneToMany(mappedBy = "permission", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<RolePermissionEntity> rolePermissions = new HashSet<>();
}
