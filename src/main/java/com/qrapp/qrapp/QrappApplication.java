package com.qrapp.qrapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class QrappApplication {

    public static void main(String[] args) {
        SpringApplication.run(QrappApplication.class, args);
    }
}
