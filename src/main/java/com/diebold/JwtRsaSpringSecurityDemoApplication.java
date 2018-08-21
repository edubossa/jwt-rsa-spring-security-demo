package com.diebold;

import com.diebold.security.rsa.RSAUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;

@SpringBootApplication
public class JwtRsaSpringSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtRsaSpringSecurityDemoApplication.class, args);
	}


	@Bean
	KeyPair keyPair(@Value("${rsa.file}") File privateKeyFile, @Value("${rsa.key}") String key)
			throws FileNotFoundException, IOException {
		return RSAUtils.readPrivateKey(new FileReader(privateKeyFile), key);
	}
}
