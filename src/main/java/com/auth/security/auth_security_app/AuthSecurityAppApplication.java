package com.auth.security.auth_security_app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthSecurityAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthSecurityAppApplication.class, args);
	}

}
