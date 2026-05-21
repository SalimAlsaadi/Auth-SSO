package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.userDTO.ServiceRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserRequestDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponseDTO;
import com.auth.security.auth_security_app.admin.superClasses.ApiResponse;

import java.util.List;

public interface UserService {

    ApiResponse create(UserRequestDTO request);

    UserResponseDTO update(Long userId, UserRequestDTO request);

    String delete(Long userId);

    UserResponseDTO getById(Long userId);

    List<UserResponseDTO> getAll();

    String toggleStatus(Long userId, boolean enabled);

    String resetPassword(Long userId, String newPassword);

    String assignRoles(Long userId, Integer roleIds);

    String assignClientsForUser(Long userId, String clients);

   // UserResponseDTO registerExternalUser(UserPublicRegistrationDTO dto);

    ApiResponse registerFromService(ServiceRegistrationDTO request);

    ApiResponse<UserResponseDTO> updateFromService(ServiceRegistrationDTO request);
}
