package com.auth.security.auth_security_app.admin.controller;


import com.auth.security.auth_security_app.admin.dto.userRoleDTO.AssignUserRoleDTO;
import com.auth.security.auth_security_app.admin.service.Implementation.UserRoleServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/userRole")
@RequiredArgsConstructor
public class UserRoleController {

    private final UserRoleServiceImpl userRoleService;

    @PostMapping("/addUserRole")
    public ResponseEntity<String> assignUserRole(@RequestBody AssignUserRoleDTO assignUserRoleDTO ){
        return ResponseEntity.ok(userRoleService.assignUserRole(assignUserRoleDTO));
    }
}
