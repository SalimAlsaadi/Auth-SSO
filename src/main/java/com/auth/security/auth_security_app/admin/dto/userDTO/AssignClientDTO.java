package com.auth.security.auth_security_app.admin.dto.userDTO;

import lombok.Data;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Data
public class AssignClientDTO {


    private Long userId;
    private List<String> clientIds;
}
