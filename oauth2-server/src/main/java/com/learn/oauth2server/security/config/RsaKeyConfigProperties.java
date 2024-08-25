package com.learn.oauth2server.security.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "rsa")
@Getter
@Setter
public class RsaKeyConfigProperties {

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;
}
