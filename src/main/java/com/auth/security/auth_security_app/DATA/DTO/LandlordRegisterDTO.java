package com.auth.security.auth_security_app.DATA.DTO;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

@Data
public class LandlordRegisterDTO {

    @NotBlank @Size(max = 100)
    private String firstName;

    @NotBlank @Size(max = 100)
    private String lastName;

    @NotBlank @Email
    private String email;

    @NotBlank
    @Pattern(regexp = "^\\+?[0-9]{10,15}$", message = "Invalid phone number")
    private String phoneNumber;

    @PastOrPresent
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;

    private String address;

    @NotBlank
    private String nationalId;

    private Boolean isActive = true;

    @NotBlank
    @Size(min = 8, max = 100, message = "Password must be at least 8 characters")
    private String password;

    // If empty or null => allow all clients (per your token customizer logic)
    private Set<String> allowedClientIds = new HashSet<>();

    // LANDLORD or TENANT
    @NotBlank
    private String refType;

    // LANDLORD (your UserDetailsService uses roles(user.getRole()))
    @NotBlank
    private String role;
}
