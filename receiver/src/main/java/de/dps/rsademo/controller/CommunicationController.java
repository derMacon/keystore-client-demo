package de.dps.rsademo.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.dps.rsademo.service.KeyStoreService;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.rsa.crypto.RsaSecretEncryptor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

@RestController
public class CommunicationController {

    @Autowired
    private KeyStoreService keyStoreService;

    @Autowired
    private ObjectMapper objectMapper;

    @SneakyThrows
    @RequestMapping("/get-public-key")
    public String getPublicKey(String publicKey) {
        PublicKey pub = keyStoreService.getAsymmetricKeyPair().getPublic();
        return objectMapper.writeValueAsString(pub);
    }

    @SneakyThrows
    @RequestMapping("/get-private-key")
    public String getPrivateKey(String privateKey) {
        PrivateKey priv = keyStoreService.getAsymmetricKeyPair().getPrivate();
        return objectMapper.writeValueAsString(priv);
    }

    @SneakyThrows
    @RequestMapping("/cipher-demo")
    public String cipherDemo(String input) {
        PublicKey pub = keyStoreService.getAsymmetricKeyPair().getPublic();
        PrivateKey priv = keyStoreService.getAsymmetricKeyPair().getPrivate();

        TextEncryptor encryptor = new RsaSecretEncryptor(pub);
        String cipher = encryptor.encrypt(input);

        TextEncryptor decryptor = new RsaSecretEncryptor(keyStoreService.getAsymmetricKeyPair());
        String message = decryptor.decrypt(cipher);
        return message;
    }

}
