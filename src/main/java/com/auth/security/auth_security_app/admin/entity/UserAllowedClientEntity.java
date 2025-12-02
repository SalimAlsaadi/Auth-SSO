package com.auth.security.auth_security_app.admin.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "user_allowed_clients")
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserAllowedClientEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private UserEntity user;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;
}
