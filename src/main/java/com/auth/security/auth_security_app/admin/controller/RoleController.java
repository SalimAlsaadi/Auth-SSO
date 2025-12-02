package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequest;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponse;
import com.auth.security.auth_security_app.admin.service.Interface.RoleService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/roles")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    // Create Role
    @PostMapping
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponse> create(@RequestBody RoleRequest request) {
        return ResponseEntity.ok(roleService.create(request));
    }

    // Update Role
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponse> update(
            @PathVariable Long id,
            @RequestBody RoleRequest request) {
        return ResponseEntity.ok(roleService.update(id, request));
    }

    // Delete Role
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<String> delete(@PathVariable Long id) {
        return ResponseEntity.ok(roleService.delete(id));
    }

    // Get All Roles
    @GetMapping
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<List<RoleResponse>> getAll() {
        return ResponseEntity.ok(roleService.getAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponse> getById(@PathVariable Long id) {
        return ResponseEntity.ok(roleService.getById(id));
    }

    // Assign Permission
    @PostMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponse> addPermission(
            @PathVariable Long roleId,
            @PathVariable Long permissionId) {
        return ResponseEntity.ok(roleService.addPermission(roleId, permissionId));
    }

    // Remove Permission
    @DeleteMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponse> removePermission(
            @PathVariable Long roleId,
            @PathVariable Long permissionId) {
        return ResponseEntity.ok(roleService.removePermission(roleId, permissionId));
    }
}
