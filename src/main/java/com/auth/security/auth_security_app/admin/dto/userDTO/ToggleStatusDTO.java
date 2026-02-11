package com.auth.security.auth_security_app.admin.dto.userDTO;

import lombok.Data;

@Data
public class ToggleStatusDTO {

    private Long userID;

    private Boolean enable;
}
