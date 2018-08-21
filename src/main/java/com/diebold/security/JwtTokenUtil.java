package com.diebold.security;

import com.diebold.security.rsa.RSAUtils;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenUtil.class);

    static final String CLAIM_KEY_IMEI = "IMEI";

    @Autowired
    private KeyPair keyPair;

    @Value("${jwt.expiration.time.minutes}")
    private int expirationTime;

    @Autowired
    @Qualifier("jwtUserDetailsService")
    private UserDetailsService userDetailsService;

    public String generateToken(UserDetails userDetails) throws JOSEException {
        Date now = new Date();
        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .issuer("https://www.dieboldnixdorf.com.br")
                .claim(CLAIM_KEY_IMEI, "862974398348287")
                .expirationTime(new Date(now.getTime() + 1000 * 60 * expirationTime))
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

    public boolean validateToken(String token, HttpServletRequest request) {
        try {
            EncryptedJWT encrypted = EncryptedJWT.parse(token);
            RSADecrypter decrypter = new RSADecrypter(keyPair.getPrivate());
            encrypted.decrypt(decrypter);
            JWTClaimsSet jwtClaims = encrypted.getJWTClaimsSet();
            log.info(jwtClaims.toJSONObject().toJSONString());
            Date now = new Date();
            Date exp = jwtClaims.getExpirationTime();
            if (now.after(exp)) {
                throw new RuntimeException("Token expired");
            }
            String username = jwtClaims.getSubject();
            log.debug("checking authentication for user '{}'", username);
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                log.info("authorizated user '{}', setting security context", username);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }
        return Boolean.TRUE;
    }

    public String encrypt(String encryptedText) throws GeneralSecurityException {
        return RSAUtils.encrypt(keyPair.getPublic(), encryptedText);
    }

    public String decrypt(String encryptedText) throws GeneralSecurityException {
        return RSAUtils.decrypt(keyPair.getPrivate(), encryptedText);
    }

}
