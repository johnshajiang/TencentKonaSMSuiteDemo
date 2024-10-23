package com.github.johnshajiang.kona.demo;

import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

public class SM2KeyAgreementDemo {

    public static void demo() throws Exception {
        KeyPair keyPair = SM2KeyPairGenDemo.genKeyPair();
        KeyPair peerKeyPair = SM2KeyPairGenDemo.genKeyPair();

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                (ECPrivateKey) keyPair.getPrivate(),
                (ECPublicKey) keyPair.getPublic(),
                (ECPublicKey) peerKeyPair.getPublic(),
                true,
                16);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2");
        keyAgreement.init(keyPair.getPrivate(), paramSpec);
        keyAgreement.doPhase(peerKeyPair.getPublic(), true);
        SecretKey sharedKey = keyAgreement.generateSecret("SM2SharedSecret");

        SM2KeyAgreementParamSpec peerParamSpec = new SM2KeyAgreementParamSpec(
                (ECPrivateKey) peerKeyPair.getPrivate(),
                (ECPublicKey) peerKeyPair.getPublic(),
                (ECPublicKey) keyPair.getPublic(),
                false,
                16);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2");
        peerKeyAgreement.init(peerKeyPair.getPrivate(), peerParamSpec);
        peerKeyAgreement.doPhase(keyPair.getPublic(), true);
        SecretKey peerSharedKey = peerKeyAgreement.generateSecret("SM2SharedSecret");

        assert Arrays.equals(sharedKey.getEncoded(), peerSharedKey.getEncoded());
    }
}
