package com.ews.security;

import org.springframework.util.StringUtils;

public class JwtAuthenticationRequest {

    private String username;
    private String password;
    private String cpf;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCpf() {
        if (!StringUtils.isEmpty(cpf)) {
            cpf = cpf.replaceAll("\\D", "");
        }
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }
}
