package com.auth.security.auth_security_app.admin.service.Implementation;

import com.auth.security.auth_security_app.admin.dto.userDTO.ServiceRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserPublicRegistrationDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserRequestDTO;
import com.auth.security.auth_security_app.admin.dto.userDTO.UserResponseDTO;

import com.auth.security.auth_security_app.admin.entity.*;
import com.auth.security.auth_security_app.admin.repository.*;

import com.auth.security.auth_security_app.admin.service.Interface.AuditLogService;
import com.auth.security.auth_security_app.admin.service.Interface.UserService;

import com.auth.security.auth_security_app.admin.superClasses.ApiResponse;
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
                user.getEnabled(),
                true, true, true,
                authorities
        );
    }



//    @Override
//    @Transactional
//    public UserResponseDTO registerExternalUser(UserPublicRegistrationDTO dto) {
//
//        if (userRepository.existsByUsername(dto.getEmail())) {
//            throw new RuntimeException("UserName already exists");
//        }
//
//        Long externalRefId = null;
//
//        // A) Call external client API if provided
//        if (dto.getExternalApiUrl() != null && !dto.getExternalApiUrl().isBlank()) {
//            externalRefId =
//                    webClient.post()
//                            .uri(dto.getExternalApiUrl())
//                            .bodyValue(dto)
//                            .retrieve()
//                            .bodyToMono(Long.class)
//                            .block();
//        }
//
//        // B) Create basic SAS user
//        UserEntity user = new UserEntity();
//        user.setUsername(dto.getEmail());
//        user.setPassword(encoder.encode(dto.getPassword()));
//        //user.setRefType( refTypeRepository.findById(dto.getRefType()).orElseThrow(() -> new RuntimeException("RefType not found")));
//        user.setRefId(externalRefId);
//        user.setEnabled(dto.getIsActive());
//
//        UserEntity saved = userRepository.save(user);
//
//        // C) Assign Roles
//        assignRoles(saved.getId(), getRoleIdsFromStrings(dto.getRoles()));
//
//        // D) Assign Allowed Clients
//        assignClientsForUser(saved.getId(), dto.getAllowedClientIds().stream().toList());
//
//
//        auditLogService.log(
//                currentUserId(),
//                "USER_CREATE",
//                "User",
//                saved.getId().toString(),
//                "Created user: " + saved.getUsername()
//        );
//
//        return getById(saved.getId());
//    }


    /* =============================================================
     *  2) USER REGISTRATION (Called from Client Apps)
     * ============================================================= */
    @Transactional
    public ApiResponse<UserResponseDTO> registerFromService(ServiceRegistrationDTO request) {

        try {

            if (request.getEmail() == null || request.getEmail().isBlank()) {
                return new ApiResponse<>(false, "Email is required", null);
            }

            if (request.getPassword() == null || request.getPassword().isBlank()) {
                return new ApiResponse<>(false, "Password is required", null);
            }

            if (userRepository.existsByUsername(request.getEmail())) {
                return new ApiResponse<>(false, "User already exists", null);
            }

            UserEntity user = UserEntity.builder()
                    .username(request.getEmail())
                    .password(encoder.encode(request.getPassword()))
                    .refId(request.getRefId())
                    .enabled(true)
                    .build();

            UserEntity saved = userRepository.save(user);

            assignRoles(saved.getId(), getRoleIdsFromStrings(request.getRoles()));

            assignClientsForUser(saved.getId(),
                    request.getAllowedClientIds());

            return new ApiResponse<>(
                    true,
                    "User registered successfully",
                    toDTO(saved)
            );

        } catch (EntityNotFoundException e) {

            return new ApiResponse<>(false, "Invalid role or client", null);

        } catch (Exception e) {

            return new ApiResponse<>(false, "Registration failed", null);
        }
    }



    @Transactional
    @Override
    public ApiResponse<UserResponseDTO> updateFromService(ServiceRegistrationDTO request) {

        try {

            if (request.getEmail() == null || request.getEmail().isBlank()) {
                return new ApiResponse<>(false, "Email is required", null);
            }

            if (request.getPassword() == null || request.getPassword().isBlank()) {
                return new ApiResponse<>(false, "Password is required", null);
            }

          UserEntity user=userRepository.findByRefId(request.getRefId()).orElseThrow(()-> new EntityNotFoundException("user not found with RefId: "+ request.getRefId()));

            user.setUsername(request.getEmail());
            user.setPassword(encoder.encode(request.getPassword()));
            user.setEnabled(true);


            UserEntity saved = userRepository.save(user);

            assignRoles(saved.getId(), getRoleIdsFromStrings(request.getRoles()));

            assignClientsForUser(saved.getId(), request.getAllowedClientIds());

            return new ApiResponse<>(
                    true,
                    "User updated successfully",
                    toDTO(saved)
            );

        } catch (EntityNotFoundException e) {

            return new ApiResponse<>(false, "Invalid role or client", null);

        } catch (Exception e) {

            return new ApiResponse<>(false, "updated failed", null);
        }
    }



    /* =============================================================
     *  3) ADMIN PANEL FUNCTIONS (CRUD)
     * ============================================================= */
    @Override
    @Transactional
    public ApiResponse<UserResponseDTO> create(UserRequestDTO request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            return new ApiResponse<>(false, "Username already exists", null);
        }

        try {

            validateAdminCreationRules(request);

            UserEntity user = new UserEntity();
            user.setUsername(request.getUsername());
            user.setPassword(encoder.encode(request.getPassword()));
            user.setEnabled(request.getEnabled());

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

            return new ApiResponse<>(true, "User created successfully", getById(saved.getId()));

        } catch (Exception e) {
            return new ApiResponse<>(false, e.getMessage(), null);
        }
    }

    @Override
    @Transactional
    public UserResponseDTO update(Long userId, UserRequestDTO request) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // 1️⃣ Validate username uniqueness
        if (request.getUsername() != null &&
                !request.getUsername().equals(user.getUsername())) {

            if (userRepository.existsByUsername(request.getUsername())) {
                throw new RuntimeException("Username already exists");
            }

            user.setUsername(request.getUsername());
        }

        // 2️⃣ Enabled status
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }

        // 3️⃣ Update password if provided
        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(encoder.encode(request.getPassword()));
        }

        // 4️⃣ Validate role rules before applying
        validateAdminCreationRules(request);

        // 5️⃣ Sync roles
        if (request.getRoleIds() != null) {
            updateUserRoles(user, request.getRoleIds());
        }

        // 6️⃣ Sync clients
        if (request.getAllowedClients() != null) {
            updateUserClients(user, request.getAllowedClients());
        }

        userRepository.save(user);

        auditLogService.log(
                currentUserId(),
                "USER_UPDATE",
                "User",
                user.getId().toString(),
                "Updated user: " + user.getUsername()
        );

        return toDTO(user);
    }


    @Override
    public UserResponseDTO getById(Long id) {
        return userRepository.findById(id)
                .map(this::toDTO)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }


    @Override
    @Transactional
    public List<UserResponseDTO> getAll() {
        return userRepository.findAll()
                .stream()
                .map(this::toDTO)
                .toList();
    }


    @Override
    @Transactional
    public String delete(Long userId) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String username = user.getUsername();

        //  prevent deleting yourself
        if (userId.equals(currentUserId())) {
            throw new RuntimeException("You cannot delete your own account");
        }

        //  prevent deleting last SAS_ADMIN
        boolean isSasAdmin = user.getRoles()
                .stream()
                .anyMatch(r -> r.getRole().getRoleName().equals("SAS_ADMIN"));

        if (isSasAdmin) {

            long adminCount = userRepository.countUsersByRole("SAS_ADMIN");

            if (adminCount <= 1) {
                throw new RuntimeException("Cannot delete the last SAS_ADMIN user");
            }
        }

        // Remove relations first
        userRoleRepository.deleteByUser(user);
        userClientRepository.deleteByUser(user);

        userRepository.delete(user);

        // Audit log
        auditLogService.log(
                currentUserId(),
                "USER_DELETE",
                "User",
                userId.toString(),
                "Deleted user: " + username
        );

        return "User deleted successfully";
    }


    @Override
    @Transactional
    public String toggleStatus(Long userId, boolean enabled) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String username = user.getUsername();

        // Prevent disabling yourself
        if (!enabled && userId.equals(currentUserId())) {
            throw new RuntimeException("You cannot disable your own account");
        }

        // Prevent disabling last SAS_ADMIN
        boolean isSasAdmin = user.getRoles()
                .stream()
                .anyMatch(r -> r.getRole().getRoleName().equals("SAS_ADMIN"));

        if (!enabled && isSasAdmin) {

            long adminCount = userRepository.countUsersByRole("SAS_ADMIN");

            if (adminCount <= 1) {
                throw new RuntimeException("Cannot disable the last SAS_ADMIN user");
            }
        }

        user.setEnabled(enabled);
        userRepository.save(user);

        auditLogService.log(
                currentUserId(),
                enabled ? "USER_ENABLE" : "USER_DISABLE",
                "User",
                userId.toString(),
                (enabled ? "Enabled user: " : "Disabled user: ") + username
        );

        return enabled ? "User enabled successfully" : "User disabled successfully";
    }


    @Override
    @Transactional
    public String resetPassword(Long userId, String newPassword) {

        if (newPassword == null || newPassword.isBlank()) {
            throw new RuntimeException("Password cannot be empty");
        }

        if (newPassword.length() < 8) {
            throw new RuntimeException("Password must be at least 8 characters");
        }

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        //prevent resetting to same password
        if (encoder.matches(newPassword, user.getPassword())) {
            throw new RuntimeException("New password must be different from current password");
        }

        user.setPassword(encoder.encode(newPassword));
        userRepository.save(user);

        // Audit log
        auditLogService.log(
                currentUserId(),
                "USER_PASSWORD_RESET",
                "User",
                userId.toString(),
                "Password reset for user: " + user.getUsername()
        );

        return "Password reset successfully";
    }


    /* =============================================================
     *  4) ROLE & CLIENT ASSIGNMENT
     * ============================================================= */

    @Override
    public String assignRoles(Long userId, Integer roleIds) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        RoleEntity role = roleRepository.findById(roleIds)
                .orElseThrow(() -> new RuntimeException("Role not found"));

        if(userRoleRepository.existsByUserAndRole (user, role)){
         return "Roles already assigned for this user";
        }




            UserRoleEntity userRole = new UserRoleEntity(null, user, role);
            user.getRoles().add(userRole);
            userRoleRepository.save(userRole);

            auditLogService.log(
                    currentUserId(),
                    "ROLE_ASSIGN",
                    "User",
                    userId.toString(),
                    "Assigned roles: " + role.getRoleName()
            );


        return "Roles updated";
    }


    @Override
    public String assignClientsForUser(Long userId, String client) {

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        ClientEntity checkClient = clientRepository.findByOauthClientId(client)
                .orElseThrow(() -> new EntityNotFoundException("Client not found: " + client));

        if (userClientRepository.existsByUserAndClient(user, checkClient)) {
            return "User already has assigned client";
        }

        UserClientEntity uc = new UserClientEntity(null, user, checkClient);

        userClientRepository.save(uc);

        return "Allowed client updated";
    }


    /* =============================================================
     *  5) ENTITY → DTO
     * ============================================================= */

    private UserResponseDTO toDTO(UserEntity user) {

        UserResponseDTO dto = new UserResponseDTO();

        dto.setUserId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEnabled(user.getEnabled());
        dto.setRefId(user.getRefId());

        dto.setRoles(
                user.getRoles()
                        .stream()
                        .map(r -> r.getRole().getRoleName())
                        .toList()
        );

        dto.setClients(
                user.getClients()
                        .stream()
                        .map(c -> c.getClient().getOauthClientId())
                        .toList()
        );


        return dto;
    }


    private Long currentUserId() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsername(username)
                .map(UserEntity::getId)
                .orElse(null);
    }



    private void validateAdminCreationRules(UserRequestDTO request) {

        List<UserRoleEntity> userRoles=userRoleRepository.findByUserIdWithRole(request.getUserId());

        List<Integer> rolesId=new ArrayList<>();

        for(UserRoleEntity userRole : userRoles){
            rolesId.add(userRole.getRole().getRoleId());
        }

        boolean isSasAdmin = roleRepository
                .findAllById(rolesId)
                .stream()
                .anyMatch(r -> r.getRoleName().equals("SAS_ADMIN"));

        if (isSasAdmin && request.getAllowedClients() != null && !request.getAllowedClients().isEmpty()) {
            throw new RuntimeException("SAS_ADMIN cannot have allowedClients");
        }

        if (!isSasAdmin && (request.getAllowedClients() == null || request.getAllowedClients().isEmpty())) {
            throw new RuntimeException("Client admins must have allowedClients");
        }
    }

    private void updateUserRoles(UserEntity user, Integer roleId) {

        userRoleRepository.deleteByUser(user);



            RoleEntity role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            UserRoleEntity ur = new UserRoleEntity(null, user, role);

            userRoleRepository.save(ur);

    }



    private void updateUserClients(UserEntity user, String client) {

        userClientRepository.deleteByUser(user);

        ClientEntity clientEntity = clientRepository.findByOauthClientId(client)
                .orElseThrow(() -> new EntityNotFoundException("Client not found: " + client));

        UserClientEntity uc = new UserClientEntity(null, user, clientEntity);

        userClientRepository.save(uc);
    }



    // Map role names → DB IDs
    private Integer getRoleIdsFromStrings(String roleNames) {
        List<Integer> roleIds = new ArrayList<>();


            RoleEntity role = roleRepository.findByRoleName(roleNames)
                    .orElseThrow(() -> new RuntimeException("Role not found: " + roleNames));




        return role.getRoleId();
    }

}
