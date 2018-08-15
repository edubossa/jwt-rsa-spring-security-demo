package com.diebold.controller;

import com.diebold.security.AuthenticationException;
import com.diebold.security.JwtAuthenticationRequest;
import com.diebold.security.JwtAuthenticationResponse;
import com.diebold.security.JwtTokenUtil;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;
import java.util.Objects;

@RestController

public class AuthenticationRestController {

    @Autowired
    private JwtTokenUtil jwtToken;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    @Qualifier("jwtUserDetailsService")
    private UserDetailsService userDetailsService;


    @PostMapping(path = "/auth")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest) {
        String token = "";
        try {
            authenticate(authenticationRequest.getUsername(), jwtToken.decrypt(authenticationRequest.getPassword()));
            final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
            token = jwtToken.generateToken(userDetails);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            e.printStackTrace();
            return new ResponseEntity<>("Can not decrypt", HttpStatus.UNAUTHORIZED);
        } catch (JOSEException e) {
            return new ResponseEntity<>("Erro token generate", HttpStatus.NOT_ACCEPTABLE);
        }
        return ResponseEntity.ok(new JwtAuthenticationResponse(token));
    }


    private void authenticate(String username, String password) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new AuthenticationException("User is disabled!", e);
        } catch (BadCredentialsException e) {
            throw new AuthenticationException("Bad credentials!", e);
        }
    }

}
