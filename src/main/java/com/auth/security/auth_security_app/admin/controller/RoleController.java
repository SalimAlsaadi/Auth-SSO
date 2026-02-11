package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleRequestDTO;
import com.auth.security.auth_security_app.admin.dto.roleDTO.RoleResponseDTO;
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
    public ResponseEntity<RoleResponseDTO> create(@RequestBody RoleRequestDTO request) {
        return ResponseEntity.ok(roleService.create(request));
    }

    // Update Role
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponseDTO> update(
            @PathVariable Integer id,
            @RequestBody RoleRequestDTO request) {
        return ResponseEntity.ok(roleService.update(id, request));
    }

    // Delete Role
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<String> delete(@PathVariable Integer id) {
        return ResponseEntity.ok(roleService.delete(id));
    }

    // Get All Roles
    @GetMapping
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<List<RoleResponseDTO>> getAll() {
        return ResponseEntity.ok(roleService.getAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponseDTO> getById(@PathVariable Integer id) {
        return ResponseEntity.ok(roleService.getById(id));
    }

    // Assign Permission
    @PostMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponseDTO> addPermission(
            @PathVariable Integer roleId,
            @PathVariable Long permissionId) {
        return ResponseEntity.ok(roleService.addPermission(roleId, permissionId));
    }

    // Remove Permission
    @DeleteMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<RoleResponseDTO> removePermission(
            @PathVariable Integer roleId,
            @PathVariable Long permissionId) {
        return ResponseEntity.ok(roleService.removePermission(roleId, permissionId));
    }
}
