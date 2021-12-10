package main;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {

    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        System.out.println("asdf");

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        char[] keyStorePassword = "server".toCharArray();
        try(InputStream keyStoreData = new FileInputStream("cdh-receiver.keystore")){  //keystore.ks       //is the file from where we want to load the file
            keyStore.load(keyStoreData, keyStorePassword);
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        PrivateKey privKey = keyPair.getPrivate();
        KeyStore.PrivateKeyEntry secretKeyEntry = new KeyStore.PrivateKeyEntry();

        keyStore.setEntry("keyAlias2", secretKeyEntry, entryPassword);


//        char[] keyStorePassword = "123abc".toCharArray();
//        try(InputStream keyStoreData = new FileInputStream("keystore.ks")){  //keystore.ks       //is the file from where we want to load the file
//            keyStore.load(keyStoreData, keyStorePassword);
//        }
    }
}
