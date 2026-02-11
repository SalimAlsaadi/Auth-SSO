package com.auth.security.auth_security_app.admin.dto.userDTO;

import com.auth.security.auth_security_app.admin.entity.ClientEntity;
import com.auth.security.auth_security_app.admin.entity.UserClientEntity;
import lombok.Data;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Data
public class UserResponseDTO {

    private Long userId;
    private String username;
    private boolean enabled;

    private String refType;
    private Long refId;

    private List<String> roles;
    private Set<UserClientEntity> clients= new HashSet<>();
}
