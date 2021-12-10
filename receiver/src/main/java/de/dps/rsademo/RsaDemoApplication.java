package de.dps.rsademo;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.rsa.crypto.RsaSecretEncryptor;
import org.springframework.web.bind.annotation.RequestMapping;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

@SpringBootApplication
@Slf4j
public class RsaDemoApplication {
//	public class RsaDemoApplication implements CommandLineRunner {

	public static void main(String[] args) {
		log.info("STARTING THE APPLICATION");
		SpringApplication.run(RsaDemoApplication.class, args);
		log.info("APPLICATION FINISHED");
	}

	@SneakyThrows
//	@Override
	public void run(String... args) {
		log.info("EXECUTING : command line runner");

		KeyStore keyStore = getKeyStore();
		CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
		X500Name x500Name = new X500Name("myName", "myOU", "myO", "myL", "myS", "myC");

		keypair.generate(2048);
		PrivateKey privKey = keypair.getPrivateKey();
		X509Certificate[] chain = new X509Certificate[1];

		int validity = 10000;
		chain[0] = keypair.getSelfCertificate(x500Name, new Date(System.currentTimeMillis()), (long) validity * 24 * 60 * 60);
		keyStore.setKeyEntry("myAlias", keypair.getPrivateKey(), "server".toCharArray(), chain);

		char[] keyStorePassword = "server".toCharArray();
		try (FileOutputStream keyStoreOutputStream = new FileOutputStream("cdh-receiver2.keystore")) {
			keyStore.store(keyStoreOutputStream, keyStorePassword);
		}

		char[] keyPassword = "server".toCharArray();
		KeyStore.ProtectionParameter entryPassword =
				new KeyStore.PasswordProtection(keyPassword);

		KeyStore.Entry keyEntry = keyStore.getEntry("myAlias", entryPassword);
		System.out.println(keyEntry);



//		keyStore.store(new FileOutputStream(".keystore"), "server");



//		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//		keyPairGenerator.initialize(1024);
//		KeyPair keyPair = keyPairGenerator.genKeyPair();
//
//		TextEncryptor encryptor = new RsaSecretEncryptor(keyPair.getPublic());
//		String cipher = encryptor.encrypt("my message");
//
//		TextEncryptor decryptor = new RsaSecretEncryptor(keyPair);
//		String message = decryptor.decrypt(cipher);

	}



	@SneakyThrows
	private static KeyStore getKeyStore() {
//		KeyStore keyStore = KeyStore.getInstance("PKCS12");
//
//		char[] keyStorePassword = "server".toCharArray();
//		try(InputStream keyStoreData = new FileInputStream("cdh-receiver.keystore")){  //keystore.ks       //is the file from where we want to load the file
//			keyStore.load(keyStoreData, keyStorePassword);
//		}

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

		char[] password = "server".toCharArray();
		ks.load(null, password);
		return ks;
	}



}
