package com.github.johnshajiang.kona.demo;

import com.tencent.kona.crypto.KonaCryptoProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.*;

@SpringBootApplication
public class KonaDemoApplication {

	static {
		Security.addProvider(new KonaCryptoProvider());
	}

	public static void main(String[] args) throws Exception {
		SM2KeyPairGenDemo.genKeyPair();

		SpringApplication.run(KonaDemoApplication.class, args);

		SM2CipherDemo.demo();
		SM2SignatureDemo.demo();
	}
}
