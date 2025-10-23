package com.selahattindev.userlibrary.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

import com.selahattindev.userlibrary.service.JwtService;

@AutoConfiguration
@ComponentScan(basePackages = "com.selahattindev.userlibrary")
@EnableConfigurationProperties(JwtProperties.class)
public class UserAutoConfiguration {

    private final JwtProperties jwtProperties;

    public UserAutoConfiguration(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Bean
    public String userLibraryInit() {
        System.out.println("✅ user-library başarıyla yüklendi!");
        return "user-library-ready";
    }

    @Bean
    public JwtService jwtService() {
        return new JwtService(jwtProperties);
    }
}