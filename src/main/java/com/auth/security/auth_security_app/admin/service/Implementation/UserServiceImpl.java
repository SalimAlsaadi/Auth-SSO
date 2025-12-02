package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.user.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.user.UserRequest;
import com.auth.security.auth_security_app.admin.dto.user.UserResponse;

import com.auth.security.auth_security_app.admin.entity.*;
import com.auth.security.auth_security_app.admin.repository.*;

import com.auth.security.auth_security_app.admin.service.Interface.UserService;

import lombok.RequiredArgsConstructor;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.springframework.web.reactive.function.client.WebClient;

import java.util.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserAllowedClientRepository allowedClientRepository;
    private final PasswordEncoder encoder;
    private final WebClient webClient;

    /* =============================================================
     *  1) USER AUTHENTICATION (Login)
     * ============================================================= */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        List<GrantedAuthority> authorities = new ArrayList<>();

        for (UserRoleEntity ur : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + ur.getRole().getRoleName()));
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                true, true, true,
                authorities
        );
    }


    /* =============================================================
     *  2) USER REGISTRATION (Called from Client Apps)
     * ============================================================= */
    @Override
    public UserResponse registerExternalUser(UserPublicRegistrationDTO dto) {

        if (userRepository.existsByUsername(dto.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        Long externalRefId = null;

        // A) Call external client API if provided
        if (dto.getExternalApiUrl() != null && !dto.getExternalApiUrl().isBlank()) {
            externalRefId =
                    webClient.post()
                            .uri(dto.getExternalApiUrl())
                            .bodyValue(dto)
                            .retrieve()
                            .bodyToMono(Long.class)
                            .block();
        }

        // B) Create basic SAS user
        UserEntity user = new UserEntity();
        user.setUsername(dto.getEmail());
        user.setPassword(encoder.encode(dto.getPassword()));
        user.setRefType(dto.getRefType());
        user.setRefId(externalRefId);
        user.setEnabled(dto.getIsActive());

        UserEntity saved = userRepository.save(user);

        // C) Assign Roles
        assignRoles(saved.getId(), getRoleIdsFromStrings(dto.getRoles()));

        // D) Assign Allowed Clients
        assignAllowedClients(saved.getId(), dto.getAllowedClientIds().stream().toList());

        return getById(saved.getId());
    }

    // Map role names → DB IDs
    private List<Long> getRoleIdsFromStrings(Set<String> roleNames) {
        List<Long> roleIds = new ArrayList<>();

        for (String name : roleNames) {
            RoleEntity role = roleRepository.findByRoleName(name)
                    .orElseThrow(() -> new RuntimeException("Role not found: " + name));

            roleIds.add(role.getRoleId());
        }

        return roleIds;
    }


    /* =============================================================
     *  3) ADMIN PANEL FUNCTIONS (CRUD)
     * ============================================================= */

    @Override
    public UserResponse create(UserRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setEnabled(request.isEnabled());
        user.setRefId(request.getRefId());
        user.setRefType(request.getRefType());

        UserEntity saved = userRepository.save(user);

        assignRoles(saved.getId(), request.getRoleIds());
        assignAllowedClients(saved.getId(), request.getAllowedClients());

        return getById(saved.getId());
    }


    @Override
    public UserResponse update(Long userId, UserRequest request) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setUsername(request.getUsername());
        user.setEnabled(request.isEnabled());
        user.setRefId(request.getRefId());
        user.setRefType(request.getRefType());

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(encoder.encode(request.getPassword()));
        }

        userRepository.save(user);

        assignRoles(userId, request.getRoleIds());
        assignAllowedClients(userId, request.getAllowedClients());

        return getById(userId);
    }


    @Override
    public UserResponse getById(Long id) {
        return userRepository.findById(id)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }


    @Override
    public List<UserResponse> getAll() {
        return userRepository.findAll()
                .stream()
                .map(this::toDTO)
                .toList();
    }


    @Override
    public String delete(Long userId) {
        userRepository.deleteById(userId);
        return "User deleted";
    }


    @Override
    public String toggleStatus(Long userId, boolean enabled) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setEnabled(enabled);
        userRepository.save(user);

        return "Status updated";
    }


    @Override
    public String resetPassword(Long userId, String newPassword) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setPassword(encoder.encode(newPassword));
        userRepository.save(user);
        return "Password reset successfully";
    }


    /* =============================================================
     *  4) ROLE & CLIENT ASSIGNMENT
     * ============================================================= */

    @Override
    public String assignRoles(Long userId, List<Long> roleIds) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        userRoleRepository.deleteByUser(user);

        for (Long roleId : roleIds) {
            RoleEntity role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            userRoleRepository.save(new UserRoleEntity(null, user, role));
        }
        return "Roles updated";
    }


    @Override
    public String assignAllowedClients(Long userId, List<String> clients) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        allowedClientRepository.deleteByUser(user);

        for (String c : clients) {
            allowedClientRepository.save(new UserAllowedClientEntity(null, user, c));
        }

        return "Allowed clients updated";
    }


    /* =============================================================
     *  5) ENTITY → DTO
     * ============================================================= */

    private UserResponse toDTO(UserEntity user) {

        UserResponse dto = new UserResponse();

        dto.setUserId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEnabled(user.isEnabled());
        dto.setRefId(user.getRefId());
        dto.setRefType(user.getRefType());

        dto.setRoles(
                user.getRoles()
                        .stream()
                        .map(r -> r.getRole().getRoleName())
                        .toList()
        );

        dto.setAllowedClients(
                user.getAllowedClients()
                        .stream()
                        .map(UserAllowedClientEntity::getClientId)
                        .toList()
        );

        return dto;
    }
}
