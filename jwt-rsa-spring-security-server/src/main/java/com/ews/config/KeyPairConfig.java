package com.ews.config;

import com.ews.security.rsa.RSAUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;

@Configuration
public class KeyPairConfig {


    @Bean
    KeyPair keyPair(@Value("${rsa.file}") File privateKeyFile, @Value("${rsa.key}") String key)
            throws FileNotFoundException, IOException {
        return RSAUtils.readPrivateKey(new FileReader(privateKeyFile), key);
    }

}
