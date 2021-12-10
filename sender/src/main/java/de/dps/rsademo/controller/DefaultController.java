package de.dps.rsademo.controller;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.rsa.crypto.RsaSecretEncryptor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@Slf4j
@RestController
public class DefaultController {

    @RequestMapping("/")
    public String index() {
        log.info("hiho");

        final String password = "I AM SHERLOCKED";
        final String salt = KeyGenerators.string().generateKey();

        TextEncryptor encryptor = Encryptors.text(password, salt);
        System.out.println("Salt: \"" + salt + "\"");

        String textToEncrypt = "*royal secrets*";
        System.out.println("Original text: \"" + textToEncrypt + "\"");

        String encryptedText = encryptor.encrypt(textToEncrypt);
        System.out.println("Encrypted text: \"" + encryptedText + "\"");

        // Could reuse encryptor but wanted to show reconstructing TextEncryptor
        TextEncryptor decryptor = Encryptors.text(password, salt);
        String decryptedText = decryptor.decrypt(encryptedText);
        System.out.println("Decrypted text: \"" + decryptedText + "\"");

        if(textToEncrypt.equals(decryptedText)) {
            System.out.println("Success: decrypted text matches");
        } else {
            System.out.println("Failed: decrypted text does not match");
        }

        return "hiho";
    }

    @SneakyThrows
    @RequestMapping("/ex2")
    public String example2() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        TextEncryptor encryptor = new RsaSecretEncryptor(keyPair.getPublic());
        String cipher = encryptor.encrypt("my message");

        TextEncryptor decryptor = new RsaSecretEncryptor(keyPair);
        String message = decryptor.decrypt(cipher);
        return message;
    }

}
