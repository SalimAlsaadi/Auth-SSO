package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.PermissionRequest;
import com.auth.security.auth_security_app.admin.entity.PermissionEntity;
import com.auth.security.auth_security_app.admin.service.Interface.PermissionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/permissions")
public class PermissionController {

    private final PermissionService service;

    public PermissionController(PermissionService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<PermissionEntity> create(@RequestBody PermissionRequest req) {
        return ResponseEntity.ok(service.createPermission(req));
    }

    @GetMapping
    public ResponseEntity<List<PermissionEntity>> all() {
        return ResponseEntity.ok(service.getAllPermissions());
    }
}
