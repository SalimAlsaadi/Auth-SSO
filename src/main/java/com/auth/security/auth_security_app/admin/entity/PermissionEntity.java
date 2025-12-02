package com.auth.security.auth_security_app.admin.entity;

import jakarta.persistence.*;
import lombok.*;

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
    private Long permissionId;

    @Column(nullable = false, unique = true, length = 100)
    private String permissionName;

    @Column(length = 200)
    private String description;
}
