package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.userDTO.UserRequest;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponse;
import com.auth.security.auth_security_app.admin.service.Interface.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping
    public ResponseEntity<UserResponse> create(@RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.create(request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserResponse> update(@PathVariable Long id, @RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.update(id, request));
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserResponse> get(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getById(id));
    }

    @GetMapping
    public ResponseEntity<List<UserResponse>> list() {
        return ResponseEntity.ok(userService.getAll());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(@PathVariable Long id) {
        return ResponseEntity.ok(userService.delete(id));
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<String> toggleStatus(@PathVariable Long id, @RequestParam boolean enabled) {
        return ResponseEntity.ok(userService.toggleStatus(id, enabled));
    }

    @PutMapping("/{id}/reset-password")
    public ResponseEntity<String> resetPassword(@PathVariable Long id, @RequestParam String newPassword) {
        return ResponseEntity.ok(userService.resetPassword(id, newPassword));
    }

    @PutMapping("/{id}/roles")
    public ResponseEntity<String> assignRoles(@PathVariable Long id, @RequestBody List<Integer> roleIds) {
        return ResponseEntity.ok(userService.assignRoles(id, roleIds));
    }

    @PutMapping("/{id}/clients")
    public ResponseEntity<String> assignClients(@PathVariable Long id, @RequestBody List<String> clientIds) {
        return ResponseEntity.ok(userService.assignAllowedClients(id, clientIds));
    }
}
