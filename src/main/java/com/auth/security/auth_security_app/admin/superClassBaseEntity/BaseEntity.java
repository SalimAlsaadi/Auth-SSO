package com.auth.security.auth_security_app.admin.superClassBaseEntity;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    /* ===============================
       AUDIT: CREATED
       =============================== */

    @CreatedBy
    @Column(name = "CreatedBy", nullable = false, updatable = false, length = 100)
    private String createdBy;

    @CreatedDate
    @Column(name = "CreationDate", nullable = false, updatable = false)
    private LocalDateTime creationDate;

    /* ===============================
       AUDIT: UPDATED
       =============================== */

    @LastModifiedBy
    @Column(name = "LastChangeBy", length = 100)
    private String lastChangeBy;

    @LastModifiedDate
    @Column(name = "LastChangeDate")
    private LocalDateTime lastChangeDate;


}

