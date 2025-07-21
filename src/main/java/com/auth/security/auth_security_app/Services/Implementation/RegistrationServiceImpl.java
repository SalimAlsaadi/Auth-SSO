package com.auth.security.auth_security_app.Services.Implementation;

import com.auth.security.auth_security_app.DATA.DTO.LandlordRegisterDTO;
import com.auth.security.auth_security_app.DATA.Entities.UserEntity;
import com.auth.security.auth_security_app.Repository.UserRepository;
import com.auth.security.auth_security_app.Services.Interface.RegistrationServiceInterface;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

@Service
public class RegistrationServiceImpl implements RegistrationServiceInterface {

    @Value("${url.api}")
    private String urlAPI;

    private final WebClient webClient;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public RegistrationServiceImpl(WebClient webClient, PasswordEncoder passwordEncoder, UserRepository userRepository){

        this.webClient = webClient;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }
    public void registerLandlord(LandlordRegisterDTO dto) {

        // Step 1: Call Resource Server to save user DATA in main DB
        Long landlordId = webClient.post()
                .uri(urlAPI)
                .bodyValue(dto)
                .retrieve()
                .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> {
                            System.out.println("Error Status Code: " + response.statusCode());
                            return response.bodyToMono(String.class)
                                    .map(body -> new RuntimeException("Failed to call Resource Server: " + body));
                        })
                .bodyToMono(Long.class)
                .block();

        // Step 2: Save user credential in Auth DB
        UserEntity user = UserEntity.builder()
                .username(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .refId(landlordId)
                .refType(dto.getRefType())
                .role(dto.getRole())
                .allowedClientIds((dto.getAllowedClientIds()))
                .build();

        userRepository.save(user);
    }
}
