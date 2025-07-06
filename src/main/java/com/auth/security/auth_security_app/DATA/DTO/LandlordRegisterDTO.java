package com.auth.security.auth_security_app.DATA.DTO;

import jakarta.validation.constraints.*;
import lombok.Data;

import java.util.Date;

@Data
public class LandlordRegisterDTO {

    @NotBlank
    @Size(max = 100)
    private String firstName;

    @NotBlank
    @Size(max = 100)
    private String lastName;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Pattern(regexp = "^\\+?[0-9]{10,15}$", message = "Invalid phone number")
    private String phoneNumber;

    @PastOrPresent
    private Date dateOfBirth;

    private String address;

    @NotBlank
    private String nationalId;

    private Boolean isActive = true; // optional (can be defaulted)

    private String password; // used in auth only, not persisted in landlord
}

