package com.auth.security.auth_security_app.admin.dto.userDTO;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

@Data
public class UserPublicRegistrationDTO {

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
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;

    private String address;

    @NotBlank
    private String nationalId;

    private Boolean isActive = true;

    @NotBlank
    @Size(min = 8)
    private String password;

    private Set<String> allowedClientIds;

    @NotBlank
    private Integer refType;

    @NotBlank
    private Set<String> roles;

    @NotBlank
    private String externalApiUrl;

}
