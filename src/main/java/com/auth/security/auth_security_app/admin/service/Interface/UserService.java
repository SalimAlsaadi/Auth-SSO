package com.auth.security.auth_security_app.admin.service.Interface;

import com.auth.security.auth_security_app.admin.dto.userDTO.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserRequest;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponse;

import java.util.List;

public interface UserService {

    UserResponse create(UserRequest request);

    UserResponse update(Long userId, UserRequest request);

    String delete(Long userId);

    UserResponse getById(Long userId);

    List<UserResponse> getAll();

    String toggleStatus(Long userId, boolean enabled);

    String resetPassword(Long userId, String newPassword);

    String assignRoles(Long userId, List<Integer> roleIds);

    String assignAllowedClients(Long userId, List<String> clientIds);

    UserResponse registerExternalUser(UserPublicRegistrationDTO dto);
}
