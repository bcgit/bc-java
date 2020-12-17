package org.bouncycastle.jsse.provider.test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server,
 * using the BC and BCJSSE providers.
 */
public class BCJSSEClientTest
{
    private static String VERSION = "TLSv1.2";
//    private static String VERSION = "TLSv1.3";

    public static void main(String[] args)
        throws Exception
    {
//        MessageDigest md = MessageDigest.getInstance("SHA256");

        ProviderUtils.setupHighPriority(false);
//        ProviderUtils.setup(false, true, false);

//        System.out.println("READY...");
//        System.in.read();

        /*
         * TEST CODE ONLY. If writing your own code based on this test case, you should configure
         * your trust manager(s) using a proper TrustManagerFactory, or else the server will be
         * completely unauthenticated.
         */
//        TrustManager tm = new X509TrustManager()
//        {
//            public X509Certificate[] getAcceptedIssuers()
//            {
//                return new X509Certificate[0];
//            }
//
//            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
//            {
//                if (chain == null || chain.length < 1 || authType == null || authType.length() < 1)
//                {
//                    throw new IllegalArgumentException();
//                }
//
//                String subject = chain[0].getSubjectX500Principal().getName();
//                System.out.println("Auto-trusted server certificate chain for: " + subject);
//            }
//
//            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
//            {
//            }
//        };

//        KeyStore keyStore = loadKeyStore("client", "/Users/peter/tmp/dtls/x509-client-rsa.pem",
//            "/Users/peter/tmp/dtls/x509-client-key-rsa.pem");
//        KeyStore trustStore = loadTrustStore("/Users/peter/tmp/dtls/x509-ca-rsa.pem");

//        KeyStore keyStore = loadKeyStore("client", "/Users/peter/tmp/dtls/x509-client-rsa_pss_256.pem",
//            "/Users/peter/tmp/dtls/x509-client-key-rsa_pss_256.pem");
//        KeyStore trustStore = loadTrustStore("/Users/peter/tmp/dtls/x509-ca-rsa_pss_256.pem");        

//        KeyStore keyStore = loadKeyStore("client", "/Users/peter/tmp/dtls/x509-client-ed25519.pem",
//            "/Users/peter/tmp/dtls/x509-client-key-ed25519.pem");
//        KeyStore trustStore = loadTrustStore("/Users/peter/tmp/dtls/x509-ca-ed25519.pem");

//        KeyStore keyStore = loadKeyStore("client", "/Users/peter/tmp/dtls/x509-client-ed448.pem",
//            "/Users/peter/tmp/dtls/x509-client-key-ed448.pem");
//        KeyStore trustStore = loadTrustStore("/Users/peter/tmp/dtls/x509-ca-ed448.pem");

//        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        SSLContext bootContext = SSLContext.getInstance(VERSION, ProviderUtils.PROVIDER_NAME_BCJSSE);

//        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
//        SSLContext bootContext = SSLContext.getInstance(VERSION);

//        kmf.init(keyStore, "password".toCharArray());
//        tmf.init(trustStore);

//        bootContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
//        bootContext.init(null, tmf.getTrustManagers(), new SecureRandom());
//        bootContext.init(null, new TrustManager[]{ tm }, new SecureRandom());
        bootContext.init(null, null, new SecureRandom());

//        bootContext.getDefaultSSLParameters();
//        bootContext.getSupportedSSLParameters();

//        for (String protocol : bootContext.getDefaultSSLParameters().getProtocols())
//        {
//            System.out.println(protocol);
//        }

        BCExtendedSSLSession sessionToResume = runInContextTimed(bootContext, null);

//        SSLContext testContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
//        testContext.init(null, null, new SecureRandom());
        SSLContext testContext = bootContext;

        runInContextTimed(testContext, sessionToResume);
    }

    private static BCExtendedSSLSession runInContextTimed(SSLContext sslContext, BCExtendedSSLSession sessionToResume)
        throws Exception
    {
        long before = System.currentTimeMillis();

        BCExtendedSSLSession result = runInContext(sslContext, sessionToResume);

        long after = System.currentTimeMillis();
        long elapsed = after - before;
        System.out.println("Elapsed: " + elapsed + "ms");

        return result;
    }

    private static BCExtendedSSLSession runInContext(SSLContext sslContext, BCExtendedSSLSession sessionToResume)
        throws Exception
    {
        String host = "www.google.com";
//        String host = "www.oracle.com";
//        String host = "www.microsoft.com";
//        String host = "tools.ietf.org";
        int port = 443;

//        String host = "localhost";
//        int port = 5556;

        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket)sslSocketFactory.createSocket(host, port);

        sslSocket.setEnabledProtocols(new String[]{ VERSION });

        if (null != sessionToResume)
        {
            ((BCSSLSocket)sslSocket).setBCSessionToResume(sessionToResume);
        }

        SSLParameters sslParameters = new SSLParameters();
//        sslParameters.setCipherSuites(new String[]{
////            "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
////            "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
//            "TLS_RSA_WITH_AES_128_CBC_SHA256",
//        });
        sslParameters.setProtocols(new String[]{ VERSION });
//        sslParameters.setProtocols(new String[]{ "TLSv1.3", "TLSv1.2" });

        if (!"localhost".equals(host))
        {
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
        }

//        sslParameters.setAlgorithmConstraints(new AlgorithmConstraints()
//        {
//            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters)
//            {
//                System.out.println("permits(1) " + algorithm);
//                return true;
//            }
//
//            public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters)
//            {
//                System.out.println("permits(2) " + algorithm);
//                return true;
//            }
//
//            public boolean permits(Set<CryptoPrimitive> primitives, Key key)
//            {
//                System.out.println("permits(3) " + key.getAlgorithm());
//                return true;
//            }
//        });

        sslSocket.setSSLParameters(sslParameters);

        sslSocket.addHandshakeCompletedListener(new HandshakeCompletedListener()
        {
            public void handshakeCompleted(HandshakeCompletedEvent event)
            {
                System.out.println("Completed : " + Hex.toHexString(event.getSession().getId()) + " ["
                    + Thread.currentThread().getName() + "]");
            }
        });

        OutputStream output = sslSocket.getOutputStream();
        writeUTF8Line(output, "GET / HTTP/1.1");
        writeUTF8Line(output, "Host: " + host + ":" + port);
        writeUTF8Line(output, "");
        output.flush();

        System.out.println("---");

        InputStream input = sslSocket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
//            System.out.println("<<< " + line);

            /*
             * TEST CODE ONLY. This is not a robust way of parsing the result!
             */
            if (line.toUpperCase().contains("</HTML>")
                || line.toUpperCase().contains("HTTP/1.1 3")
                || line.toUpperCase().contains("HTTP/1.1 4")
                )
            {
                break;
            }
        }

        System.out.flush();

        sslSocket.close();

        SSLSession origSession = sslSocket.getSession();

        BCExtendedSSLSession session = ((BCSSLSocket)sslSocket).getBCSession();
        session.getPeerCertificateChain();

        System.out.println("Session ID: " + Hex.toHexString(origSession.getId()));

        return session;
    }

    private static void writeUTF8Line(OutputStream output, String line)
        throws IOException
    {
        output.write((line + "\r\n").getBytes("UTF-8"));
        System.out.println(">>> " + line);
    }

    private static KeyStore createKeyStore() throws Exception
    {
//        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12", ProviderUtils.PROVIDER_NAME_BC);
        keyStore.load(null, null);
        return keyStore;
    }

    private static X509Certificate loadCertificate(String certPath) throws Exception
    {
        byte[] certEncoding = loadPEMContents(certPath, "CERTIFICATE");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certEncoding));
    }

    private static PrivateKey loadKey(String keyPath) throws Exception
    {
        byte[] keyEncoding = loadPEMContents(keyPath, "PRIVATE KEY");

        return loadPkcs8PrivateKey(keyEncoding);

//        PemObject pem = loadPemResource(resource);
//        if (pem.getType().equals("PRIVATE KEY"))
//        {
//            return loadJcaPkcs8PrivateKey(crypto, pem.getContent());
//        }
//        if (pem.getType().equals("ENCRYPTED PRIVATE KEY"))
//        {
//            throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");
//        }
//        if (pem.getType().equals("RSA PRIVATE KEY"))
//        {
//            RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
//            KeyFactory keyFact = crypto.getHelper().createKeyFactory("RSA");
//            return keyFact.generatePrivate(new RSAPrivateCrtKeySpec(rsa.getModulus(), rsa.getPublicExponent(),
//                rsa.getPrivateExponent(), rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(), rsa.getExponent2(),
//                rsa.getCoefficient()));
//        }
    }

    private static KeyStore loadKeyStore(String alias, String certPath, String keyPath) throws Exception
    {
        X509Certificate cert = loadCertificate(certPath);
        PrivateKey key = loadKey(keyPath);

        KeyStore keyStore = createKeyStore();
        keyStore.setKeyEntry(alias, key, "password".toCharArray(), new X509Certificate[]{ cert });
        return keyStore;
    }

    private static KeyStore loadTrustStore(String caPath) throws Exception
    {
        X509Certificate caCert = loadCertificate(caPath);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", caCert);
        return trustStore;
    }

    private static byte[] loadPEMContents(String path, String type) throws IOException
    {
        InputStream s = new FileInputStream(path);
        PemReader p = new PemReader(new InputStreamReader(s));
        PemObject o = p.readPemObject();
        p.close();

        if (!o.getType().endsWith(type))
        {
            return null;
        }

        return o.getContent();
    }

    static PrivateKey loadPkcs8PrivateKey(byte[] encoded) throws GeneralSecurityException
    {
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(encoded);
        AlgorithmIdentifier algID = pki.getPrivateKeyAlgorithm();
        ASN1ObjectIdentifier oid = algID.getAlgorithm();

        String name;
        if (X9ObjectIdentifiers.id_dsa.equals(oid))
        {
            name = "DSA";
        }
        else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid))
        {
            // TODO Try ECDH/ECDSA according to intended use?
            name = "EC";
        }
        else if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)
            || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid))
        {
            name = "RSA";
        }
        else if (EdECObjectIdentifiers.id_Ed25519.equals(oid))
        {
            name = "Ed25519";
        }
        else if (EdECObjectIdentifiers.id_Ed448.equals(oid))
        {
            name = "Ed448";
        }
        else
        {
            name = oid.getId();
        }

        KeyFactory kf = KeyFactory.getInstance(name);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

}
