package com.learn.oauth2server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.SecureRandom;
import java.util.Base64;

@SpringBootApplication
public class Oauth2ServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2ServerApplication.class, args);
	}

//	public static void main(String[] args) {
//		// Create an instance of SecureRandom
//		SecureRandom random = new SecureRandom();
//
//		// Generate a 32-byte random byte array
//		byte[] randomBytes = new byte[32];
//		random.nextBytes(randomBytes);
//
//		// Convert to a Base64 string representation (optional)
//		String base64String = Base64.getEncoder().encodeToString("39ad111e279cbfe1c0160071577db2454d44ec0af4f50575649cf3e7970967ca".getBytes());
//
//		// Print the result
//		System.out.println("32-byte string (Base64): " + base64String);
//	}

}
