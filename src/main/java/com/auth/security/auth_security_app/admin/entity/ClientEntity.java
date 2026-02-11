package com.auth.security.auth_security_app.admin.entity;
import com.auth.security.auth_security_app.admin.superClassBaseEntity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Entity
@Table(
        name = "sas_clients",
        uniqueConstraints = {
                @UniqueConstraint(name="UK_SAS_CLIENT_CODE", columnNames="clientCode"),
                @UniqueConstraint(name="UK_SAS_OAUTH_CLIENT_ID", columnNames="oauthClientId")
        })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    // Business
    @Column(nullable = false)
    private String clientCode;

    @Column(nullable = false)
    private String clientName;

    @Column
    private String clientDescription;

    // OAuth (REQUIRED)
    @Column(nullable = false, unique = true)
    private String oauthClientId;

    @Column(nullable = false)
    private boolean publicClient; // PKCE

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "sas_client_redirects")
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "sas_client_scopes")
    private Set<String> scopes;

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<UserClientEntity> userClientEntity;

}








