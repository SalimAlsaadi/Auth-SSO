package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.userDTO.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserRequestDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponseDTO;

import java.util.List;

public interface UserService {

    UserResponseDTO create(UserRequestDTO request);

    UserResponseDTO update(Long userId, UserRequestDTO request);

    String delete(Long userId);

    UserResponseDTO getById(Long userId);

    List<UserResponseDTO> getAll();

    String toggleStatus(Long userId, boolean enabled);

    String resetPassword(Long userId, String newPassword);

    String assignRoles(Long userId, List<Integer> roleIds);

    String assignClientsForUser(Long userId, List<String> clientIds);

    UserResponseDTO registerExternalUser(UserPublicRegistrationDTO dto);
}
