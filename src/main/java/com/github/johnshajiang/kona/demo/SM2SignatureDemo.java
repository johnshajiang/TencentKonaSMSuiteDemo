package com.github.johnshajiang.kona.demo;

import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;

import java.security.*;
import java.security.interfaces.ECPublicKey;

public class SM2SignatureDemo {

    private static final byte[] MESSAGE = "signature message".getBytes();

    public static void demo() throws Exception {
        KeyPair keyPair = SM2KeyPairGenDemo.genKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey priKey = keyPair.getPrivate();

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec((ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2");
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2");
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        assert verifier.verify(signature);
    }
}
