package com.auth.security.auth_security_app.admin.dto;

import java.util.List;

public record RoleRequest(
        String roleName,
        String description,
        List<String> permissions
) {}
