package com.github.johnshajiang.kona.demo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_TAG_LEN;

public class SM4Demo {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = toBytes("000000000000000000000000");

    private static final byte[] MESSAGE = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    public static void demo() throws Exception {
        cbc();
        ctr();
        ecb();
        gcm();
    }

    private static void cbc() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        assert Arrays.equals(MESSAGE, cleartext);
    }

    private static void ctr() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        assert Arrays.equals(MESSAGE, cleartext);
    }

    private static void ecb() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        assert Arrays.equals(MESSAGE, cleartext);
    }

    private static void gcm() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        assert Arrays.equals(MESSAGE, cleartext);
    }
}
