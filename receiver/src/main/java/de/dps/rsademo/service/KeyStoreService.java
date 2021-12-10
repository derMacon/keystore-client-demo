package de.dps.rsademo.service;

import de.dps.rsademo.model.KeyStoreProperties;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

// todo remove sneaky throws from methods
@Service
public class KeyStoreService {

    @Autowired
    private KeyStoreProperties ksProps;

    private KeyStore keyStore;

    private PrivateKey pk;

    @PostConstruct
    private void init() {
//        if (new File(ksProps.getFilename()).exists()) {
//            loadExistingKeyStore();
//        } else {
            createNewKeyStore();
            genKeyPair();
//        }
    }

    @SneakyThrows
    private void createNewKeyStore() {
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] password = ksProps.getKeyStorePass().toCharArray();
        keyStore.load(null, password);
    }

    @SneakyThrows
    private void loadExistingKeyStore() {
		keyStore = KeyStore.getInstance("PKCS12");
		char[] keyStorePassword = ksProps.getKeyStorePass().toCharArray();
		try(InputStream keyStoreData = new FileInputStream(ksProps.getFilename())){
			keyStore.load(keyStoreData, keyStorePassword);
		}
    }

    public KeyPair getAsymmetricKeyPair() {
        return new KeyPair(getPublicKey(), getPrivateKey());
    }

    @SneakyThrows
    private PublicKey getPublicKey() {

        String content = new String(keyStore.getKey(ksProps.getPubKeyAlias(), "server".toCharArray()).getEncoded(), StandardCharsets.UTF_8);

//        byte[] byteKey = Base64.decode(key.getBytes(), Base64.DEFAULT);
//        byte[] byteKey = Base64.getDecoder().decode(content);
        byte[] byteKey = keyStore.getKey(ksProps.getPubKeyAlias(), "server".toCharArray()).getEncoded();
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePublic(X509publicKey);
    }


    @SneakyThrows
    private PrivateKey getPrivateKey() {
        KeyStore.ProtectionParameter entryPassword =
                new KeyStore.PasswordProtection(ksProps.getKeyStorePass().toCharArray());

        KeyStore.Entry keyEntry = keyStore.getEntry(ksProps.getPrivKeyAlias(), entryPassword);
        return ((PrivateKey)((KeyStore.PrivateKeyEntry) keyEntry).getPrivateKey());
    }

    public void genKeyPair() {
        CertAndKeyGen keyPair = createKeyCertGenerator();
        setKeyPairEntry(keyPair);
        saveKeystore();
    }

    @SneakyThrows
    private CertAndKeyGen createKeyCertGenerator() {
        CertAndKeyGen keyPair = new CertAndKeyGen(ksProps.getKeyType(), ksProps.getSigAlg(), null);
        keyPair.generate(ksProps.getKeyBits());
        return keyPair;
    }

    @SneakyThrows
    private void setKeyPairEntry(CertAndKeyGen keyPair) {
        X500Name x500Name = new X500Name(
                ksProps.getCommonName(),
                ksProps.getOrganizationUnit(),
                ksProps.getOrganizationName(),
                ksProps.getLocalityName(),
                ksProps.getStateName(),
                ksProps.getCountry()
        );

        X509Certificate[] chain = new X509Certificate[] {
            keyPair.getSelfCertificate(
                    x500Name,
                    new Date(System.currentTimeMillis()),
                    (long) ksProps.getDaysValidity() * 24 * 60 * 60
            )
        };

        keyStore.setKeyEntry(
                ksProps.getPrivKeyAlias(),
                keyPair.getPrivateKey(),
                ksProps.getPrivKeyPass().toCharArray(),
                chain
        );

        pk = keyPair.getPrivateKey(); // todo remove


        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(ksProps.getKeyStorePass().toCharArray());
//        SecretKey mySecretKey = new SecretKeySpec("this is a test".getBytes(StandardCharsets.UTF_8), "DSA");
        SecretKey mySecretKey = new SecretKeySpec(keyPair.getPublicKey().getEncoded(), "DSA");
        testbytes = keyPair.getPublicKey().getEncoded();
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(mySecretKey);
        keyStore.setEntry(ksProps.getPubKeyAlias(), secretKeyEntry, protectionParam);


    }

    private byte[] testbytes;

    @SneakyThrows
    private void saveKeystore() {
        char[] keyStorePassword = ksProps.getKeyStorePass().toCharArray();
        try (FileOutputStream keyStoreOutputStream = new FileOutputStream(ksProps.getFilename())) {
            keyStore.store(keyStoreOutputStream, keyStorePassword);
        }
    }

}
