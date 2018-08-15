package com.diebold.security;

import com.diebold.security.rsa.RSAUtils;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenUtil.class);

    @Autowired
    private KeyPair keyPair;

    @Value("${jwt.expiration.time.minutes}")
    private int expirationTime;

    public String generateToken(UserDetails userDetails) throws JOSEException {
        Date now = new Date();

        // Prepare JWT with claims set
        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .issuer("https://www.dieboldnixdorf.com.br")
                .claim("android_version", "1.0.1")
                .claim("ios_version", "2.0.0")
                .expirationTime(new Date(now.getTime() + (1000 * 60 * expirationTime)))
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();

        log.info(jwtClaims.toJSONObject().toJSONString());

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512);
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
        RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
        jwt.encrypt(encrypter);
        return jwt.serialize();
    }


    public String encrypt(String encryptedText) throws GeneralSecurityException {
        return RSAUtils.encrypt(keyPair.getPublic(), encryptedText);
    }

    public String decrypt(String encryptedText) throws GeneralSecurityException {
        return RSAUtils.decrypt(keyPair.getPrivate(), encryptedText);
    }

}
