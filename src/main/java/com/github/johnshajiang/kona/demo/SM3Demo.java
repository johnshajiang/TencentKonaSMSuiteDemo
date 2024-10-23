package com.github.johnshajiang.kona.demo;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Arrays;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

public class SM3Demo {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] MESSAGE = toBytes("616263");
    private static final byte[] DIGEST = toBytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    public static void demo() throws Exception {
        digest();
        mac();
    }

    private static void digest() throws Exception {
        MessageDigest sm3 = MessageDigest.getInstance("SM3");
        byte[] digest = sm3.digest(MESSAGE);
        assert Arrays.equals(MESSAGE, digest);
    }

    private static void mac() throws Exception {
        Mac sm3mac = Mac.getInstance("SM3HMac");
        sm3mac.init(new SecretKeySpec(KEY, "HmacSM3"));
        byte[] mac = sm3mac.doFinal(MESSAGE);
        assert Arrays.equals(MESSAGE, mac);
    }
}
