package com.auth.security.auth_security_app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthSecurityAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthSecurityAppApplication.class, args);
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		boolean matches = encoder.matches("StrongPass123!", "$2a$10$shvICtbidiK/H6Js6VM5Y.MT1AlKI8rAqoQuefuiZCgy4poVg/D.q");
		System.out.println(matches);
	}

}
