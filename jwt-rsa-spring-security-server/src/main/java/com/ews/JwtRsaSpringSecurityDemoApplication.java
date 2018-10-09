package com.ews;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Acesso ao BD - http://localhost:8080/h2-console
 * jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
 *
 *
 * https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption
 *
 * Openssl
 * https://www.openssl.org/source/
 * https://rietta.com/blog/2012/01/27/openssl-generating-rsa-key-from-command/
 *
 * # Private Key - voce pode adicionar uma senha pra criptrogravar a geracao do certificado .
 * openssl genrsa -des3 -out private.pem 2048
 *
 * # Private Key - Gera o certificado sem precisar passar senha
 * openssl genrsa -out servcore-private.pem 2048
 *
 * # Public key.
 * openssl rsa -in private.pem -outform PEM -pubout -out public.pem
 */
@SpringBootApplication
public class JwtRsaSpringSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtRsaSpringSecurityDemoApplication.class, args);
	}

}
