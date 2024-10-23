package com.github.johnshajiang.kona.demo;

import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.ssl.KonaSSLProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.*;

@SpringBootApplication
public class KonaDemoApplication {

	static {
		Security.addProvider(new KonaCryptoProvider());
		Security.addProvider(new KonaPKIXProvider());
		Security.addProvider(new KonaSSLProvider());
	}

	public static void main(String[] args) throws Exception {
		SpringApplication.run(KonaDemoApplication.class, args);

		SM2KeyPairGenDemo.genKeyPair();
		System.out.println("SM2 key pair generation demo ended");

		SM2CipherDemo.demo();
		System.out.println("SM2 cipher demo ended");

		SM2SignatureDemo.demo();
		System.out.println("SM2 signature demo ended");

		SM2KeyAgreementDemo.demo();
		System.out.println("SM2 key agreement demo ended");

		SM3Demo.demo();
		System.out.println("SM3 demo ended");

		SM4Demo.demo();
		System.out.println("SM4 demo ended");

		new TLCPEngineDemo().demo();
		System.out.println("TLCP engine demo ended");

		new TLCPSocketDemo().demo();
		System.out.println("TLCP socket demo started");

		new TLS13SocketDemo().demo();
		System.out.println("TLS 1.3 socket demo started");
	}
}
