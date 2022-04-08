package org.bouncycastle.test.est;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.CACertsResponse;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.EnrollmentResponse;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.SimpleTest;

public class TestServerKeyGeneration
    extends SimpleTest
{


    private static final String ca = "-----BEGIN CERTIFICATE-----\n" +
        "MIIBuDCCAV+gAwIBAgIBATAKBggqhkjOPQQDAjAyMTAwLgYDVQQDEydOb24tUHJv\n" +
        "ZHVjdGlvbiBUZXN0aW5nIFJvb3QgQ0EgaDlCaDhUWWkwHhcNMjIwNDA4MDAwMDQ1\n" +
        "WhcNMjIwNDA5MDAwMDQ1WjAyMTAwLgYDVQQDEydOb24tUHJvZHVjdGlvbiBUZXN0\n" +
        "aW5nIFJvb3QgQ0EgaDlCaDhUWWkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5\n" +
        "+kq7LlVAr1HWAIB4w8lfiiwi+cRrCbxR7tjyBXAkeA3wQ+ErkC9f8qge8OAHKNZ6\n" +
        "R09m1oMbBzWUrmyl8gkQo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\n" +
        "BgEB/wIBATAdBgNVHQ4EFgQUb3fqxptJnhpKRWgz+lK4LCSbdF0wHwYDVR0jBBgw\n" +
        "FoAUb3fqxptJnhpKRWgz+lK4LCSbdF0wCgYIKoZIzj0EAwIDRwAwRAIgG5JG0jrQ\n" +
        "+TcS9jSyKnK0UOyM8Oq+ZVViOZuOviXYlKgCIAE2nMK2OBJZR3rnkw924Q5rr+cg\n" +
        "F2GpHhBxbbwSNfGN\n" +
        "-----END CERTIFICATE-----\n";

    public String getName()
    {
        return "test against cisto est server";
    }

    public void performTest()
        throws Exception
    {
        serverGenWithoutEncryption();
    }


    public void serverGenWithoutEncryption()
        throws Exception
    {
        //
        // This test requires an instance of https://github.com/globalsign/est to be running.
        // We will try and fetch the CA certs and if that is not possible the test will skip.
        //

        Object[] caCerts = null;

        try
        {
            ESTService svc = new JsseESTServiceBuilder("localhost:8443", JcaJceUtils.getTrustAllTrustManager()).build();
            CACertsResponse resp = svc.getCACerts();
            caCerts = ESTService.storeToArray(resp.getCertificateStore());
        }
        catch (ESTException ex)
        {
            skip("skipping, unable to fetch CA certs, assume no EST server.");
        }


        ESTService est = new JsseESTServiceBuilder(
            "localhost:8443", JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(caCerts), null)
        ).withProvider(BouncyCastleJsseProvider.PROVIDER_NAME).withTLSVersion("TLS").build();

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair enrollmentPair = kpg.generateKeyPair();

        PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), enrollmentPair.getPublic());


        PKCS10CertificationRequest csr = pkcs10Builder.build(
            new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

        SecureRandom nonceRandom = new SecureRandom();


        // new JcaHttpAuthBuilder("estuser", "estpwd".toCharArray()).setNonceGenerator(nonceRandom).setProvider("BC").build()
        try
        {
            EnrollmentResponse enr = est.simpleEnrollWithServersideCreation(csr, null);
            PrivateKeyInfo pki = enr.getPrivateKeyInfo();

            //
            // Not testing if the server is generating sane keys.
            // Did we get a private key info and at least one certificate
            //
            if (pki == null)
            {
                fail("expecting pki");
            }

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];
            if (enrolledAsHolder == null)
            {
                fail("expecting certificate");
            }
        }
        catch (ESTException estException)
        {
            System.out.println();
            Streams.pipeAll(estException.getBody(), System.out);
            System.out.println();
        }
        System.out.println();
    }


    public static void main(String[] args)
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        runTest(new TestServerKeyGeneration());
    }

}
