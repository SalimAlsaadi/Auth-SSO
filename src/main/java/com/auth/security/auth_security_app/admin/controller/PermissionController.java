package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionRequestDTO;
import com.auth.security.auth_security_app.admin.dto.permissionDTO.PermissionResponseDTO;
import com.auth.security.auth_security_app.admin.service.Interface.PermissionService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionService permissionService;

    @PostMapping
    public ResponseEntity<PermissionResponseDTO> create(@RequestBody PermissionRequestDTO request) {
        return ResponseEntity.ok(permissionService.create(request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<PermissionResponseDTO> update(
            @PathVariable Long id,
            @RequestBody PermissionRequestDTO request) {
        return ResponseEntity.ok(permissionService.update(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(@PathVariable Long id) {
        return ResponseEntity.ok(permissionService.delete(id));
    }

    @GetMapping
    public ResponseEntity<List<PermissionResponseDTO>> getAll() {
        return ResponseEntity.ok(permissionService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<PermissionResponseDTO> getById(@PathVariable Long id) {
        return ResponseEntity.ok(permissionService.getById(id));
    }
}
