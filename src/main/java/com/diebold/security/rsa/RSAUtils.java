package com.diebold.security.rsa;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * # Private Key - Generates certificate with password
 * > openssl genrsa -des3 -out private-des.pem 2048
 *
 * # Private Key - Generates the certificate without having to use a password
 * > openssl genrsa -out private.pem 2048
 *
 * # Generated Public Key
 * > openssl rsa -in private.pem -out servcore-public.pem -pubout
 *
 */
public class RSAUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encrypt(Key key, String text) throws GeneralSecurityException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(rsa.doFinal(text.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decrypt(Key key, String encryptedText) throws GeneralSecurityException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, key);
        return new String(rsa.doFinal(Base64.getDecoder().decode(encryptedText)), StandardCharsets.UTF_8);
    }

    public static PublicKey readPublicKey(Reader publicKeyReader) throws IOException {
        try (PEMParser pemParser = new PEMParser(publicKeyReader)) {
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            return new JcaPEMKeyConverter().setProvider("BC").getPublicKey(subjectPublicKeyInfo);
        }
    }

    public static KeyPair readPrivateKey(Reader privateKeyReader, String password) throws IOException {
        try (PEMParser pemParser = new PEMParser(privateKeyReader)) {
            Object obj = pemParser.readObject();
            PEMKeyPair pemKeyPair = null;
            if (obj instanceof PEMKeyPair) {
                pemKeyPair = (PEMKeyPair) obj;
            } else if (obj instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
                pemKeyPair = encryptedKeyPair.decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()));
            }
            return new JcaPEMKeyConverter().setProvider("BC").getKeyPair(pemKeyPair);
        }
    }


}
