package com.auth.security.auth_security_app.Services.Implementation;

import com.auth.security.auth_security_app.DATA.DTO.UserDTO;
import com.auth.security.auth_security_app.DATA.Entities.UserEntity;
import com.auth.security.auth_security_app.Repository.UserRepository;
import com.auth.security.auth_security_app.Services.Interface.RegistrationServiceInterface;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashSet;

@Service
public class RegistrationServiceImpl implements RegistrationServiceInterface {

    @Value("${url.api}")
    private String urlAPI;

    private final WebClient webClient;
    private final PasswordEncoder encoder;
    private final UserRepository repo;

    public RegistrationServiceImpl(WebClient webClient, PasswordEncoder encoder, UserRepository repo) {
        this.webClient = webClient;
        this.encoder = encoder;
        this.repo = repo;
    }

    @Override
    public void registerLandlord(UserDTO dto) {

        // Call Main App to create landlord
        Long landlordId = webClient.post()
                .uri(urlAPI)
                .bodyValue(dto)
                .retrieve()
                .bodyToMono(Long.class)
                .block();

        UserEntity entity = UserEntity.builder()
                .username(dto.getEmail())
                .password(encoder.encode(dto.getPassword()))
                .role(dto.getRole())
                .refType(dto.getRefType())
                .refId(landlordId)
                .allowedClientIds(dto.getAllowedClientIds() == null ? new HashSet<>() : dto.getAllowedClientIds())
                .build();

        repo.save(entity);
    }
}
