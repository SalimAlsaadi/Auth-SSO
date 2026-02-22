package com.auth.security.auth_security_app.admin.entity;

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

//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "ref_type_id", foreignKey = @ForeignKey(name = "FK_users_ref_type"))
//    private ClientRefTypeEntity refType;


    @Column(name = "is_enable")
    private boolean enabled;


    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    private Set<UserRoleEntity> roles = new HashSet<>();

    @Builder.Default
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<UserClientEntity> clients = new HashSet<>();

}
