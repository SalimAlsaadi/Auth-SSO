package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.user.UserRequest;
import com.auth.security.auth_security_app.admin.dto.user.UserResponse;
import com.auth.security.auth_security_app.admin.service.Interface.UserService;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final UserService userService;

    // Create User
    @PostMapping
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<UserResponse> create(@RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.create(request));
    }

    // Update User
    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<UserResponse> update(@PathVariable Long userId, @RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.update(userId, request));
    }

    // Get All
    @GetMapping
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<List<UserResponse>> getAll() {
        return ResponseEntity.ok(userService.getAll());
    }

    // Get Single
    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<UserResponse> getById(@PathVariable Long userId) {
        return ResponseEntity.ok(userService.getById(userId));
    }

    // Delete
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<String> delete(@PathVariable Long userId) {
        return ResponseEntity.ok(userService.delete(userId));
    }

    // Enable/Disable
    @PatchMapping("/{userId}/status")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<String> toggleStatus(@PathVariable Long userId, @RequestParam boolean enabled) {
        return ResponseEntity.ok(userService.toggleStatus(userId, enabled));
    }

    // Reset Password
    @PatchMapping("/{userId}/reset-password")
    @PreAuthorize("hasRole('SAS_ADMIN')")
    public ResponseEntity<String> resetPassword(@PathVariable Long userId, @RequestParam String newPassword) {
        return ResponseEntity.ok(userService.resetPassword(userId, newPassword));
    }

}
