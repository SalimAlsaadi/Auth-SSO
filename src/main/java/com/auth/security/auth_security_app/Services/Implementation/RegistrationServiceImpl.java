package com.auth.security.auth_security_app.Services.Implementation;

import com.auth.security.auth_security_app.DATA.DTO.LandlordRegisterDTO;
import com.auth.security.auth_security_app.DATA.Entities.UserEntity;
import com.auth.security.auth_security_app.Repository.UserRepository;
import com.auth.security.auth_security_app.Services.Interface.RegistrationServiceInterface;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class RegistrationServiceImpl implements RegistrationServiceInterface {

    private final WebClient webClient;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public RegistrationServiceImpl(WebClient webClient, PasswordEncoder passwordEncoder, UserRepository userRepository){

        this.webClient = webClient;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }
    public void registerLandlord(LandlordRegisterDTO dto) {

        // Step 1: Call Resource Server to save landlord
        Long landlordId = webClient.post()
                .uri("http://localhost:8008/api/landlords/register")
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

        // Step 2: Save user in Auth DB
        UserEntity user = UserEntity.builder()
                .username(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .refId(landlordId)
                .refType("LANDLORD")
                .role("LANDLORD")
                .build();

        userRepository.save(user);
    }
}
