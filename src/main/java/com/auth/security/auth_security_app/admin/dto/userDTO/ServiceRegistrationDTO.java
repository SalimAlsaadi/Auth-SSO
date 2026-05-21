package com.auth.security.auth_security_app.admin.dto.userDTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class ServiceRegistrationDTO {

    @NotBlank
    private String email;

    @NotBlank
    @Size(min = 8)
    private String password;


    @NotNull
    private Long refId;       // returned from AQARK

    @NotEmpty
    private String roles ;

    @NotEmpty
    private String allowedClientIds ;
}
