package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.userDTO.ServiceRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserRequestDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponseDTO;

import com.auth.security.auth_security_app.admin.entity.*;
import com.auth.security.auth_security_app.admin.repository.*;

import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;
import com.auth.security.auth_security_app.admin.service.Interface.UserService;

import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

import org.springframework.security.core.context.SecurityContextHolder;
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
    private final UserClientRepository userClientRepository;
    private final PasswordEncoder encoder;
    private final WebClient webClient;
    private final AuditLogService auditLogService;
    private final ClientRepository clientRepository;
    /* =============================================================
     *  1) USER AUTHENTICATION (Login)
     * ============================================================= */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity user = userRepository.findByUsernameWithRoles(username)
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
    @Transactional
    public UserResponseDTO registerExternalUser(UserPublicRegistrationDTO dto) {

        if (userRepository.existsByUsername(dto.getEmail())) {
            throw new RuntimeException("UserName already exists");
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
        //user.setRefType( refTypeRepository.findById(dto.getRefType()).orElseThrow(() -> new RuntimeException("RefType not found")));
        user.setRefId(externalRefId);
        user.setEnabled(dto.getIsActive());

        UserEntity saved = userRepository.save(user);

        // C) Assign Roles
        assignRoles(saved.getId(), getRoleIdsFromStrings(dto.getRoles()));

        // D) Assign Allowed Clients
        assignClientsForUser(saved.getId(), dto.getAllowedClientIds().stream().toList());


        auditLogService.log(
                currentUserId(),
                "USER_CREATE",
                "User",
                saved.getId().toString(),
                "Created user: " + saved.getUsername()
        );

        return getById(saved.getId());
    }

    @Transactional
    public UserResponseDTO registerFromService(ServiceRegistrationDTO request) {

        if (userRepository.existsByUsername(request.getEmail())) {
            throw new RuntimeException("User already exists");
        }

        UserEntity user = UserEntity.builder()
                .username(request.getEmail())
                .password(encoder.encode(request.getPassword()))
                .refId(request.getRefId())
                .enabled(true)
                .build();


        UserEntity saved = userRepository.save(user);

        // C) Assign Roles
        assignRoles(saved.getId(), getRoleIdsFromStrings(request.getRoles()));

        // D) Assign Allowed Clients
        assignClientsForUser(saved.getId(), request.getAllowedClientIds().stream().toList());

        return toDTO(saved);
    }

    // Map role names → DB IDs
    private List<Integer> getRoleIdsFromStrings(Set<String> roleNames) {
        List<Integer> roleIds = new ArrayList<>();

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
    public UserResponseDTO create(UserRequestDTO request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setEnabled(request.isEnabled());
        user.setRefId(request.getRefId());

        UserEntity saved = userRepository.save(user);

        assignRoles(saved.getId(), request.getRoleIds());
        assignClientsForUser(saved.getId(), request.getAllowedClients());

        auditLogService.log(
                currentUserId(),
                "USER_CREATE",
                "User",
                saved.getId().toString(),
                "Created user: " + saved.getUsername()
        );

        return getById(saved.getId());
    }


    @Override
    public UserResponseDTO update(Long userId, UserRequestDTO request) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        user.setUsername(request.getUsername());
        user.setEnabled(request.isEnabled());
        user.setRefId(request.getRefId());

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(encoder.encode(request.getPassword()));
        }

        userRepository.save(user);

        assignRoles(userId, request.getRoleIds());
        assignClientsForUser(userId, request.getAllowedClients());

        auditLogService.log(
                currentUserId(),
                "USER_UPDATE",
                "User",
                user.getId().toString(),
                "Updated user details"
        );

        return getById(userId);
    }


    @Override
    public UserResponseDTO getById(Long id) {
        return userRepository.findById(id)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }


    @Override
    public List<UserResponseDTO> getAll() {
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
        UserEntity user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));

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
    public String assignRoles(Long userId, List<Integer> roleIds) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));


        for (Integer roleId : roleIds) {
            RoleEntity role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            UserRoleEntity userRole = new UserRoleEntity(null, user, role);
            user.getRoles().add(userRole);
            userRoleRepository.save(userRole);

            auditLogService.log(
                    currentUserId(),
                    "ROLE_ASSIGN",
                    "User",
                    userId.toString(),
                    "Assigned roles: " + roleId
            );

        }
        return "Roles updated";
    }


    @Override
    public String assignClientsForUser(Long userId, List<String> clients) {

        UserEntity user = userRepository.findById(userId).orElseThrow(() -> new EntityNotFoundException("User not found"));
        List<ClientEntity> checkClients=clientRepository.findByOauthClientIdIn(clients);



        for (ClientEntity client : checkClients) {

            UserClientEntity uc = new UserClientEntity(null, user, client);

            user.getClients().add(uc);

            userClientRepository.save(uc);
        }

        return "Allowed clients updated";
    }


    /* =============================================================
     *  5) ENTITY → DTO
     * ============================================================= */

    private UserResponseDTO toDTO(UserEntity user) {

        UserResponseDTO dto = new UserResponseDTO();

        dto.setUserId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEnabled(user.isEnabled());
        dto.setRefId(user.getRefId());

        dto.setRoles(
                user.getRoles()
                        .stream()
                        .map(r -> r.getRole().getRoleName())
                        .toList()
        );

        dto.setClients(
                user.getClients() == null
                        ? new HashSet<>()
                        : new HashSet<>(user.getClients())
        );


        return dto;
    }

    private Long currentUserId() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .map(UserEntity::getId)
                .orElse(null);
    }



}
