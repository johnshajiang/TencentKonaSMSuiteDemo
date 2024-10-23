/*
 * Copyright (c) 2003, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

// SunJSSE does not support dynamic system properties, no way to re-use
// system properties in samevm/agentvm mode.

package com.github.johnshajiang.kona.demo;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class TLCPEngineDemo {

    protected final SSLEngine clientEngine;     // client Engine
    protected final ByteBuffer clientOut;       // write side of clientEngine
    protected final ByteBuffer clientIn;        // read side of clientEngine

    protected final SSLEngine serverEngine;     // server Engine
    protected final ByteBuffer serverOut;       // write side of serverEngine
    protected final ByteBuffer serverIn;        // read side of serverEngine

    // For data transport, this example uses local ByteBuffers.  This
    // isn't really useful, but the purpose of this example is to show
    // SSLEngine concepts, not how to do network transport.
    protected final ByteBuffer cTOs;      // "reliable" transport client->server
    protected final ByteBuffer sTOc;      // "reliable" transport server->client

    // Trusted certificates.
    protected final static Cert[] TRUSTED_CERTS = { Cert.CA_CERT} ;

    // End entity certificate.
    protected final static Cert[] SERVER_CERTS = {
            Cert.SERVER_SIGN_CERT, Cert.SERVER_ENC_CERT};
    protected final static Cert[] CLIENT_CERTS = {
            Cert.CLIENT_SIGN_CERT, Cert.CLIENT_ENC_CERT};

    protected TLCPEngineDemo() throws Exception {
        serverEngine = configureServerEngine(
                createServerSSLContext().createSSLEngine());

        clientEngine = configureClientEngine(
                createClientSSLContext().createSSLEngine());

        // We'll assume the buffer sizes are the same
        // between client and server.
        SSLSession session = clientEngine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();

        // We'll make the input buffers a bit bigger than the max needed
        // size, so that unwrap()s following a successful data transfer
        // won't generate BUFFER_OVERFLOWS.
        //
        // We'll use a mix of direct and indirect ByteBuffers for
        // tutorial purposes only.  In reality, only use direct
        // ByteBuffers when they give a clear performance enhancement.
        clientIn = ByteBuffer.allocate(appBufferMax + 50);
        serverIn = ByteBuffer.allocate(appBufferMax + 50);

        cTOs = ByteBuffer.allocateDirect(netBufferMax);
        sTOc = ByteBuffer.allocateDirect(netBufferMax);

        clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
    }

    /*
     * Create an instance of SSLContext with the specified trust/key materials.
     */
    public static SSLContext createSSLContext(
            Cert[] trustedCerts,
            Cert[] endEntityCerts,
            ContextParameters params) throws Exception {

        KeyStore ts = null;     // trust store
        KeyStore ks = null;     // key store
        char[] passphrase = "passphrase".toCharArray();

        // Generate certificate from cert string.
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");

        // Import the trused certs.
        ByteArrayInputStream is;
        if (trustedCerts != null && trustedCerts.length != 0) {
            ts = KeyStore.getInstance("PKCS12", "KonaPKIX");
            ts.load(null, null);

            Certificate[] trustedCert = new Certificate[trustedCerts.length];
            for (int i = 0; i < trustedCerts.length; i++) {
                is = new ByteArrayInputStream(trustedCerts[i].certStr.getBytes());
                try {
                    trustedCert[i] = cf.generateCertificate(is);
                } finally {
                    is.close();
                }

                ts.setCertificateEntry(
                        "trusted-cert-" + trustedCerts[i].name(), trustedCert[i]);
            }
        }

        // Import the key materials.
        if (endEntityCerts != null && endEntityCerts.length != 0) {
            ks = KeyStore.getInstance("PKCS12", "KonaPKIX");
            ks.load(null, null);

            for (int i = 0; i < endEntityCerts.length; i++) {
                // generate the private key.
                PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(
                        Base64.getMimeDecoder().decode(endEntityCerts[i].privKeyStr));
                KeyFactory kf = KeyFactory.getInstance(
                        endEntityCerts[i].keyAlgo, "KonaCrypto");
                PrivateKey priKey = kf.generatePrivate(priKeySpec);

                // generate certificate chain
                is = new ByteArrayInputStream(
                        endEntityCerts[i].certStr.getBytes());
                Certificate keyCert = null;
                try {
                    keyCert = cf.generateCertificate(is);
                } finally {
                    is.close();
                }

                Certificate[] chain = new Certificate[] { keyCert };

                // import the key entry.
                ks.setKeyEntry("cert-" + endEntityCerts[i].name(),
                        priKey, passphrase, chain);
            }
        }

        // Create an SSLContext object.
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(params.tmAlgorithm, "KonaSSL");
        tmf.init(ts);

        SSLContext context = SSLContext.getInstance(params.contextProtocol, "KonaSSL");
        if (endEntityCerts != null && endEntityCerts.length != 0 && ks != null) {
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(params.kmAlgorithm, "KonaSSL");
            kmf.init(ks, passphrase);

            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } else {
            context.init(null, tmf.getTrustManagers(), null);
        }

        return context;
    }

    /*
     * Create an instance of SSLContext for client use.
     */
    protected SSLContext createClientSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, CLIENT_CERTS,
                getClientContextParameters());
    }

    /*
     * Create an instance of SSLContext for server use.
     */
    protected SSLContext createServerSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, SERVER_CERTS,
                getServerContextParameters());
    }

    /*
     * The parameters used to configure SSLContext.
     */
    protected static final class ContextParameters {
        final String contextProtocol;
        final String tmAlgorithm;
        final String kmAlgorithm;

        ContextParameters(String contextProtocol,
                          String tmAlgorithm, String kmAlgorithm) {

            this.contextProtocol = contextProtocol;
            this.tmAlgorithm = tmAlgorithm;
            this.kmAlgorithm = kmAlgorithm;
        }
    }

    /*
     * Get the client side parameters of SSLContext.
     */
    protected ContextParameters getClientContextParameters() {
        return new ContextParameters("TLCP", "PKIX", "NewSunX509");
    }

    /*
     * Get the server side parameters of SSLContext.
     */
    protected ContextParameters getServerContextParameters() {
        return new ContextParameters("TLCP", "PKIX", "NewSunX509");
    }

    /*
     * ==================
     * Run the test case.
     */
    public void demo() throws Exception {
        runTest();
    }

    //
    // Protected methods could be used to customize the test case.
    //

    /*
     * Configure the client side engine.
     */
    protected SSLEngine configureClientEngine(SSLEngine clientEngine) {
        clientEngine.setUseClientMode(true);

        // Get/set parameters if needed
        // SSLParameters paramsClient = clientEngine.getSSLParameters();
        // clientEngine.setSSLParameters(paramsClient);

        return clientEngine;
    }

    /*
     * Configure the server side engine.
     */
    protected SSLEngine configureServerEngine(SSLEngine serverEngine) {
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(true);

        // Get/set parameters if needed
        //
        // SSLParameters paramsServer = serverEngine.getSSLParameters();
        // serverEngine.setSSLParameters(paramsServer);

        return serverEngine;
    }

    //
    // Private methods that used to build the common part of the test.
    //

    private void runTest() throws Exception {
        SSLEngineResult clientResult;
        SSLEngineResult serverResult;

        boolean dataDone = false;
        while (isOpen(clientEngine) || isOpen(serverEngine)) {
            log("=================");

            // client wrap
            log("---Client Wrap---");
            clientResult = clientEngine.wrap(clientOut, cTOs);
            logEngineStatus(clientEngine, clientResult);
            runDelegatedTasks(clientEngine);

            // server wrap
            log("---Server Wrap---");
            serverResult = serverEngine.wrap(serverOut, sTOc);
            logEngineStatus(serverEngine, serverResult);
            runDelegatedTasks(serverEngine);

            cTOs.flip();
            sTOc.flip();

            // client unwrap
            log("---Client Unwrap---");
            clientResult = clientEngine.unwrap(sTOc, clientIn);
            logEngineStatus(clientEngine, clientResult);
            runDelegatedTasks(clientEngine);

            // server unwrap
            log("---Server Unwrap---");
            serverResult = serverEngine.unwrap(cTOs, serverIn);
            logEngineStatus(serverEngine, serverResult);
            runDelegatedTasks(serverEngine);

            cTOs.compact();
            sTOc.compact();

            // After we've transferred all application data between the client
            // and server, we close the clientEngine's outbound stream.
            // This generates a close_notify handshake message, which the
            // server engine receives and responds by closing itself.
            if (!dataDone && (clientOut.limit() == serverIn.position()) &&
                    (serverOut.limit() == clientIn.position())) {

                // A sanity check to ensure we got what was sent.
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                log("\tClosing clientEngine's *OUTBOUND*...");
                clientEngine.closeOutbound();
                logEngineStatus(clientEngine);

                dataDone = true;
                log("\tClosing serverEngine's *OUTBOUND*...");
                serverEngine.closeOutbound();
                logEngineStatus(serverEngine);
            }
        }
    }

    static boolean isOpen(SSLEngine engine) {
        return (!engine.isOutboundDone() || !engine.isInboundDone());
    }

    private static void logEngineStatus(SSLEngine engine) {
        log("\tCurrent HS State: " + engine.getHandshakeStatus());
        log("\tisInboundDone() : " + engine.isInboundDone());
        log("\tisOutboundDone(): " + engine.isOutboundDone());
    }

    private static void logEngineStatus(
            SSLEngine engine, SSLEngineResult result) {
        log("\tResult Status    : " + result.getStatus());
        log("\tResult HS Status : " + result.getHandshakeStatus());
        log("\tEngine HS Status : " + engine.getHandshakeStatus());
        log("\tisInboundDone()  : " + engine.isInboundDone());
        log("\tisOutboundDone() : " + engine.isOutboundDone());
        log("\tMore Result      : " + result);
    }

    private static void log(String message) {
//        System.err.println(message);
    }

    // If the result indicates that we have outstanding tasks to do,
    // go ahead and run them in this thread.
    protected static void runDelegatedTasks(SSLEngine engine) throws Exception {
        if (engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                log("    running delegated task...");
                runnable.run();
            }
            HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
            logEngineStatus(engine);
        }
    }

    // Simple check to make sure everything came across as expected.
    static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            log("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    public enum Cert {

        CA_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBjDCCATKgAwIBAgIUc1kBltJcsvucxFYD+CzKcGvuNHowCgYIKoEcz1UBg3Uw\n" +
                "EjEQMA4GA1UEAwwHdGxjcC1jYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgxMTU2\n" +
                "MzhaMBUxEzARBgNVBAMMCnRsY3AtaW50Y2EwWTATBgcqhkjOPQIBBggqgRzPVQGC\n" +
                "LQNCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7RlsFspKwF5LMxkcYMblZXjlUYVhnpN\n" +
                "F3N/x2knleNfrXrdTTR3Yv2MIMGQo2MwYTAdBgNVHQ4EFgQURS/dNZJ+d0Sel9TW\n" +
                "vGNYGWnxTb4wHwYDVR0jBBgwFoAUQI8lwKZzxP/OpobF4UNyPG3JiocwDwYDVR0T\n" +
                "AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSAAwRQIhAI79\n" +
                "0T0rhbYCdqdGqbYxidgyr1XRpXncwRqmx7a+IDkvAiBDPtfFfB/UiwO4wBLqxwJO\n" +
                "+xEdTF+d/Wfro9fxSnrqEw==\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgl8tSMRCrTmAjuddY\n" +
                "5ATvA35iDKydBgVQkLPLpxjmTFChRANCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7Rl\n" +
                "sFspKwF5LMxkcYMblZXjlUYVhnpNF3N/x2knleNfrXrdTTR3Yv2MIMGQ"),
        SERVER_SIGN_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkjCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwMwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3Atc2VydmVyLXNpZ24wWTATBgcqhkjOPQIB\n" +
                "BggqgRzPVQGCLQNCAARYT1t4ecS5pLkQlA9smyxe1tictMdl/x4AbO8nI07CHjXK\n" +
                "HPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuODo2AwXjAdBgNVHQ4EFgQUIerW\n" +
                "JjprHQfhD6ETgBX0G8dWWGswHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
                "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSAAw\n" +
                "RQIgW88b4/7Rgj0QVkHR49zINniwxdjotBRkSwdKNkVtt7YCIQCkjttpnM3HU0v7\n" +
                "NYFodEcndjXj9RDGujYO9NxgegXpSg==\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg6wAH+egoZkKS3LKi\n" +
                "0okzJSYrn/yRVhNfmdhySuJic5ahRANCAARYT1t4ecS5pLkQlA9smyxe1tictMdl\n" +
                "/x4AbO8nI07CHjXKHPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuOD"),
        SERVER_ENC_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkDCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwYwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3Atc2VydmVyLWVuYzBZMBMGByqGSM49AgEG\n" +
                "CCqBHM9VAYItA0IABAQbatb13gJL3zt1B8U5LoheRJ+4XnRpqIQ5Osx0VDk4UW25\n" +
                "8aLlU96bf3onvnHThpa9GwHbY5BpYsMP1hS+1kCjYDBeMB0GA1UdDgQWBBQ0KNMH\n" +
                "KtXGecDXiEtTjCfhpDh5CDAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
                "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNHADBE\n" +
                "AiAD2eC+F7kTZGbH2lHG7ZTOzx62OYo1MSn31+hKHfbZ9AIgazWIQMJ0MQfn/qX5\n" +
                "z0Ez8iVqyDxZyHIOFjbr1DZEQEk=\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqFilR+zUyRQWREb+\n" +
                "rb5uIldK/bPE1l20DzNpuMt55VehRANCAAQEG2rW9d4CS987dQfFOS6IXkSfuF50\n" +
                "aaiEOTrMdFQ5OFFtufGi5VPem396J75x04aWvRsB22OQaWLDD9YUvtZA"),
        CLIENT_SIGN_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkzCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwQwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3AtY2xpZW50LXNpZ24wWTATBgcqhkjOPQIB\n" +
                "BggqgRzPVQGCLQNCAASPBt+HBVc3bmQkKHNR6EQVdSS905HiiOphVGuDwHrMpzUm\n" +
                "Qh3C4zNqdSlp0PUS8NK3imLBpMxng+FMnM6bDefXo2AwXjAdBgNVHQ4EFgQUM7U5\n" +
                "/ErJ5ZdOZVUGvFqUAQyW70AwHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
                "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSQAw\n" +
                "RgIhANKxFf6vSIWsACuxWGCG4/uJmc82jAIKCCrWH09KIt5kAiEA0XGSRL+mZu2L\n" +
                "1jf5zKhE6ASDdV634fDEknKcsLkuvvU=\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgulutgxQDiBzTCYiu\n" +
                "adobFrKgK/umEjLmUKTUjUKXVI+hRANCAASPBt+HBVc3bmQkKHNR6EQVdSS905Hi\n" +
                "iOphVGuDwHrMpzUmQh3C4zNqdSlp0PUS8NK3imLBpMxng+FMnM6bDefX"),
        CLIENT_ENC_CERT(
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBkTCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwcwCgYIKoEcz1UBg3Uw\n" +
                "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
                "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3AtY2xpZW50LWVuYzBZMBMGByqGSM49AgEG\n" +
                "CCqBHM9VAYItA0IABF8BHUkVbNgU/EmoZlSAWbPcMHuV2LZU62AJElRf/ZasTmMH\n" +
                "uhdtOAnoIkvuBh+yJZBjKM/0avFAbCDY5Mjo8RKjYDBeMB0GA1UdDgQWBBSjHJvH\n" +
                "aqrfqkgfyR7af6BSlPyXHTAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
                "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNIADBF\n" +
                "AiEAwBlUP46RdSR2eBgMe30DcMXDUcdv/W1stRGWS0znQB0CIG2pC+yOAe+R97JW\n" +
                "Nvbb8xtPrMYkjrU5emCH2H0a6eHz\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqrW1N+3YxmSDz7KX\n" +
                "dCH238n62DR6/3Fw4723EaMFh2GhRANCAARfAR1JFWzYFPxJqGZUgFmz3DB7ldi2\n" +
                "VOtgCRJUX/2WrE5jB7oXbTgJ6CJL7gYfsiWQYyjP9GrxQGwg2OTI6PES");

        final String keyAlgo = "EC";
        final String certStr;
        final String privKeyStr;

        Cert(String certStr, String privKeyStr) {
            this.certStr = certStr;
            this.privKeyStr = privKeyStr;
        }
    }
}
