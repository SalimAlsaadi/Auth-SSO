package com.auth.security.auth_security_app.admin.controller;

import com.auth.security.auth_security_app.admin.dto.userDTO.*;
import com.auth.security.auth_security_app.admin.service.Interface.UserService;
import com.auth.security.auth_security_app.admin.superClasses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

//    @PostMapping
//    public ResponseEntity<UserResponseDTO> create(@RequestBody UserPublicRegistrationDTO request) {
//        return ResponseEntity.ok(userService.registerExternalUser(request));
//    }

    @PostMapping("/service")
    public ResponseEntity<ApiResponse<Long>> registerFromExternalSystems(@RequestBody ServiceRegistrationDTO request) {

        ApiResponse<UserResponseDTO> result = userService.registerFromService(request);

        if (!result.isSuccess()) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, result.getMessage(), null));
        }

        return ResponseEntity.ok(
                new ApiResponse<>(true, "User created", result.getData().getUserId()));
    }

    @PutMapping("/service")
    public ResponseEntity<ApiResponse<Long>> updateFromExternalSystems(@RequestBody ServiceRegistrationDTO request) {

        ApiResponse<UserResponseDTO> result = userService.updateFromService(request);

        if (!result.isSuccess()) {
            return ResponseEntity.badRequest().body(new ApiResponse<>(false, result.getMessage(), null));
        }

        return ResponseEntity.ok(
                new ApiResponse<>(true, "User updated", result.getData().getUserId()));
    }



    @PostMapping("/createAdmins")
    public ResponseEntity<ApiResponse<UserResponseDTO>> createAdmins(@RequestBody UserRequestDTO dto){
        return ResponseEntity.ok(userService.create(dto));
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
