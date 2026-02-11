package com.auth.security.auth_security_app.admin.dto.userDTO;

import lombok.Data;

import java.util.List;

@Data
public class AssignRoleDTO {

    private Long userId;

    private List<Integer> roleIds;
}
