package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.userDTO.*;
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
    public ResponseEntity<UserResponseDTO> create(@RequestBody UserPublicRegistrationDTO request) {
        return ResponseEntity.ok(userService.registerExternalUser(request));
    }

    @PutMapping("/updateUserDetails")
    public ResponseEntity<UserResponseDTO> update(@RequestBody UserRequestDTO request) {
        return ResponseEntity.ok(userService.update(request.getUserId(), request));
    }

    @PostMapping("/getUserById")
    public ResponseEntity<UserResponseDTO> getUserById(@RequestBody UserIdDTO userIdDTO) {
        return ResponseEntity.ok(userService.getById(userIdDTO.getUserId()));
    }

    @PostMapping("/getAllUsers")
    public ResponseEntity<List<UserResponseDTO>> getAll(){
        return ResponseEntity.ok(userService.getAll());
    }

    @PutMapping("/deleteUser")
    public ResponseEntity<String> delete(@RequestBody UserIdDTO userIdDTO) {
        return ResponseEntity.ok(userService.delete(userIdDTO.getUserId()));
    }

    @PutMapping("/status")
    public ResponseEntity<String> toggleStatus(@RequestBody ToggleStatusDTO toggleStatusDTO) {
        return ResponseEntity.ok(userService.toggleStatus(toggleStatusDTO.getUserID(), toggleStatusDTO.getEnable()));
    }

    @PutMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ChangPswDTO changPswDTO) {
        return ResponseEntity.ok(userService.resetPassword(changPswDTO.getUserId(), changPswDTO.getPassword()));
    }

    @PostMapping("/{id}/roles")
    public ResponseEntity<String> assignRoles(@RequestBody AssignRoleDTO assignRoleDTO) {
        return ResponseEntity.ok(userService.assignRoles(assignRoleDTO.getUserId(), assignRoleDTO.getRoleIds()));
    }

    @PostMapping("/assignClients")
    public ResponseEntity<String> assignClients(@RequestBody AssignClientDTO assignClientDTO) {
        return ResponseEntity.ok(userService.assignClientsForUser(assignClientDTO.getUserId(), assignClientDTO.getClientIds()));
    }
}
