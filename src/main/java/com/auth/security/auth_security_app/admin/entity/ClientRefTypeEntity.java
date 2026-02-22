//package com.auth.security.auth_security_app.admin.entity;
//
//import jakarta.persistence.*;
//import lombok.*;
//
//import java.time.LocalDateTime;
//
//@Entity
//@Table(name = "client_ref_types", uniqueConstraints = {
//                                @UniqueConstraint(name = "UK_client_ref_types", columnNames = {"client_id", "ref_type_name"}  )  })
//@Setter
//@Getter
//@AllArgsConstructor
//@NoArgsConstructor
//@Builder
//public class ClientRefTypeEntity {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Integer id;
//
//
//    @Builder.Default
//    @ManyToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name = "client_id", nullable = false, foreignKey = @ForeignKey(name = "FK_client_ref_types_client"))
//    private ClientEntity client;
//
//
//    @Column(name = "ref_type_name", nullable = false, length = 50)
//    private String refTypeName;
//
//    @Column(length = 255)
//    private String description;
//
//
//    @Column(name = "created_at", updatable = false)
//    private LocalDateTime createdAt;
//
//    @Column(name = "updated_at")
//    private LocalDateTime updatedAt;
//
//
//    @PrePersist
//    public void onCreate() {
//        this.createdAt = LocalDateTime.now();
//    }
//
//    @PreUpdate
//    public void onUpdate() {
//        this.updatedAt = LocalDateTime.now();
//    }
//}
