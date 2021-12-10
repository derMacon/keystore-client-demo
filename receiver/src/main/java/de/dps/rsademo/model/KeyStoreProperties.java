package de.dps.rsademo.model;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "ks")
@Getter
@Setter
public class KeyStoreProperties {
    private String filename;
    private String keyStorePass;
    private String keyStoreName;
    private String pubKeyAlias;
    private String pubKeyPass;
    private String privKeyAlias;
    private String privKeyPass;

    private String commonName;
    private String organizationUnit;
    private String organizationName;
    private String localityName;
    private String stateName;
    private String country;

    private String keyType;
    private String sigAlg;

    private int keyBits;
    private int daysValidity;
}
