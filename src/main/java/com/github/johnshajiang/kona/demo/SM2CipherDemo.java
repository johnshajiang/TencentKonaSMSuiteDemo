package com.github.johnshajiang.kona.demo;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class SM2CipherDemo {

    private static final byte[] MESSAGE = "cipher message".getBytes();

    static void demo() throws Exception {
        KeyPair keyPair = SM2KeyPairGenDemo.genKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey priKey = keyPair.getPrivate();

        Cipher cipher = Cipher.getInstance("SM2");

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        System.out.println("decrypted: " + Arrays.equals(MESSAGE, cleartext));
    }
}
