package com.github.johnshajiang.kona.demo;

import java.security.*;

public class SM2KeyPairGenDemo {

    public static KeyPair genKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2");
        return keyPairGenerator.generateKeyPair();
    }
}
