//package com.auth.security.auth_security_app.Services.Implementation;
//
//import com.auth.security.auth_security_app.DATA.DTO.UserDTO;
//import com.auth.security.auth_security_app.admin.entity.UserEntity;
//import com.auth.security.auth_security_app.admin.repository.UserRepository;
//import com.auth.security.auth_security_app.Services.Interface.RegistrationServiceInterface;
//import com.auth.security.auth_security_app.admin.entity.RoleEntity;
//import com.auth.security.auth_security_app.admin.repository.RoleRepository;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//import org.springframework.web.reactive.function.client.WebClient;
//
//import java.util.HashSet;
//import java.util.Set;
//
//@Service
//public class RegistrationServiceImpl implements RegistrationServiceInterface {
//
////    @Value("${url.api}")
////    private String urlAPI;
//
//    private final WebClient webClient;
//    private final PasswordEncoder encoder;
//    private final UserRepository userRepo;
//    private final RoleRepository roleRepo;
//
//    public RegistrationServiceImpl(WebClient webClient, PasswordEncoder encoder, UserRepository userRepo, RoleRepository roleRepo) {
//        this.webClient = webClient;
//        this.encoder = encoder;
//        this.userRepo = userRepo;
//        this.roleRepo=roleRepo;
//    }
//
//    @Override
//    public void registerUser(UserDTO dto) {
//
//        Long externalRefId = null;
//
//        // --- 1. If external system is provided, call it ---
//        if (dto.getExternalApiUrl() != null && !dto.getExternalApiUrl().isBlank()) {
//            externalRefId = webClient.post()
//                    .uri(dto.getExternalApiUrl())
//                    .bodyValue(dto)
//                    .retrieve()
//                    .bodyToMono(Long.class)
//                    .block();
//        }
//
//        // --- 2. Assign roles (USER as default) ---
//        Set<RoleEntity> roles = new HashSet<>();
//
//        RoleEntity defaultRole = roleRepo.findByRoleName("USER")
//                .orElseThrow(() -> new RuntimeException("Default USER role not found"));
//
//        roles.add(defaultRole);
//
//        if (dto.getRoles() != null) {
//            dto.getRoles().forEach(r -> {
//                roleRepo.findByRoleName(r).ifPresent(roles::add);
//            });
//        }
//
//        // --- 3. Create SAS user ---
//        UserEntity user = UserEntity.builder()
//                .username(dto.getEmail())
//                .password(encoder.encode(dto.getPassword()))
//                .roles(roles)
//                .refType(dto.getRefType())       // Example: LANDLORD, TENANT, STUDENT
//                .refId(externalRefId)            // ID returned by the Main App
//                .allowedClientIds(dto.getAllowedClientIds())
//                .build();
//
//        userRepo.save(user);
//    }
//
//}
