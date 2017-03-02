package org.bouncycastle.test.est;


import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLHandshakeException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.EnrollmentResponse;
import org.bouncycastle.est.HttpAuth;
import org.bouncycastle.est.jcajce.ChannelBindingProvider;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaHttpAuthBuilder;
import org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class TestEnroll
    extends SimpleTest
{

    public String getName()
    {
        return "TestEnroll";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestEnroll.class);
    }


    // Start a server instance that uses basic auth.
    // But disables the POP validation.
    private ESTServerUtils.ServerInstance startDefaultServerTLSAndBasicAuth(int delay, boolean popOn)
        throws Exception
    {
        final ESTServerUtils.EstServerConfig config = new ESTServerUtils.EstServerConfig();
        config.serverCertPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.serverKeyPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.realm = "estreal";
        config.verbose = true;
        config.tcpPort = 8443;
        config.useBasicAuth = true;
        config.useDigestAuth = false;
        config.estTRUSTEDCerts = ESTServerUtils.makeRelativeToServerHome("trustedcerts.crt").getCanonicalPath();
        config.estCACERTSResp = ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt").getCanonicalPath();
        config.disableHTTPAuth = false;
        config.enableCheckPOPtoTLSUID = popOn;
        config.manualEnroll = delay;


        //
        // Read in openssl config, and adjust it with the correct path.
        //

        String cnf = ESTTestUtils.readToString(ESTServerUtils.makeRelativeToServerHome("/estExampleCA.cnf"));
        cnf = cnf.replace("= ./estCA", "= " + ESTServerUtils.makeRelativeToServerHome("/estCA").getCanonicalPath());
        config.openSSLConfigFile = cnf;

        return ESTServerUtils.startServer(config);

    }


    /**
     * Test enrollment with digest auth.
     * <p>
     * NB: The digest as of 2016-Feb-03 is hard coded in the server.
     *
     * @return
     * @throws Exception
     */
    private ESTServerUtils.ServerInstance startDefaultServerWithDigestAuth()
        throws Exception
    {

        final ESTServerUtils.EstServerConfig config = new ESTServerUtils.EstServerConfig();
        config.serverCertPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.serverKeyPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.realm = "estrealm";
        config.verbose = true;
        config.tcpPort = 8443;
        config.useBasicAuth = false;
        config.useDigestAuth = true;
        config.estTRUSTEDCerts = ESTServerUtils.makeRelativeToServerHome("trustedcerts.crt").getCanonicalPath();
        config.estCACERTSResp = ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt").getCanonicalPath();

        //
        // Read in openssl config, and adjust it with the correct path.
        //

        String cnf = ESTTestUtils.readToString(ESTServerUtils.makeRelativeToServerHome("/estExampleCA.cnf"));
        cnf = cnf.replace("= ./estCA", "= " + ESTServerUtils.makeRelativeToServerHome("/estCA").getCanonicalPath());
        config.openSSLConfigFile = cnf;

        return ESTServerUtils.startServer(config);

    }


    @Test
    public void testEnrollUsingBasicAuth()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;

        try
        {
            serverInstance = startDefaultServerTLSAndBasicAuth(0, false);

            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            ESTService est = new JcaESTServiceBuilder(
                "https://localhost:8443/.well-known/est/", sfcb.build()
            ).build();


//            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/", ).build();
            //
            // Make certificate request.
            //

            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();

            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            EnrollmentResponse enr = est.simpleEnroll(false, csr,
                new JcaHttpAuthBuilder("estreal", "estuser", "estpwd".toCharArray())
                    .setNonceGenerator(new SecureRandom()).setProvider("BC").build());
            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());


        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }
    }


    @Test
    public void testEnrollUsingBasicAuthWithDelay()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;

        try
        {
            serverInstance = startDefaultServerTLSAndBasicAuth(5, false);

            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            ESTService est = new JcaESTServiceBuilder(
                "https://localhost:8443/.well-known/est/", sfcb.build()
            ).build();

            //
            // Make certificate request.
            //

            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();

            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            EnrollmentResponse enr = est.simpleEnroll(false, csr, new HttpAuth("estreal", "estuser", "estpwd".toCharArray(), new SecureRandom(), new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()));


            Assert.assertFalse("Can Retry is true.", enr.canRetry());
            Assert.assertNull("Store is null", enr.getStore());
            Assert.assertFalse("Must not be completed:?", enr.isCompleted());

            System.out.println(enr.getNotBefore() - System.currentTimeMillis());
            Assert.assertTrue("Future time reasonable?", enr.getNotBefore() - System.currentTimeMillis() > 2000);

            int max = 100;
            while (!enr.canRetry() && --max > 0)
            {
                Thread.sleep(500);
            }
            Assert.assertTrue("Wait looped out.", max > 0);

            Assert.assertTrue("Can we retry?", enr.canRetry());


            EnrollmentResponse entTriedAgain = est.simpleEnroll(enr);

            Assert.assertTrue("Must be completed:?", entTriedAgain.isCompleted());

            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(entTriedAgain.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());


        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }
    }


    /**
     * Perform enrollment using digest auth.
     *
     * @throws Exception
     */
    @Test
    public void testEnrollUsingDigestAuth()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServerWithDigestAuth();


            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            ESTService est = new JcaESTServiceBuilder(
                "https://localhost:8443/.well-known/est/", sfcb.build()
            ).build();
            //
            // Make certificate request.
            //

            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();

            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            SecureRandom nonceRandom = new SecureRandom();
            EnrollmentResponse enr = est.simpleEnroll(false, csr,
                new JcaHttpAuthBuilder("estuser", "estpwd".toCharArray()).setNonceGenerator(nonceRandom).setProvider("BC").build());
            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());
        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }
    }


    /**
     * @return [privateKey, X509Certificate]
     * @throws Exception
     */
    private static Object[] bogusCAGenerator()
        throws Exception
    {
        //
        // Create a self signed certificate to tend as trust anchor that will
        // not be part of the servers path.
        //

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.C, "AI");
        builder.addRDN(BCStyle.CN, "BogusCA");
        builder.addRDN(BCStyle.O, "BogusCA providers.");
        builder.addRDN(BCStyle.L, "Atlantis");

        X500Name name = builder.build();

        return new Object[]{originalKeyPair.getPrivate(), ESTTestUtils.createSelfsignedCert("SHA256WITHECDSA",
            name,
            SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
            originalKeyPair.getPrivate(),
            1
        )};
    }


    /**
     * Test enrollment using TLS do do the client authentication.
     * In this test we are going to use the BC API to generate a client certificate that the server will NOT accept.
     *
     * @throws Exception
     */
    @Test
    public void testEnrollUsingBogusTLSClientAuthAndBasicAuth()
        throws Exception
    {
        ESTTestUtils.ensureProvider();

        X509CertificateHolder caCert = ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/extCA/cacert.crt")
        );

        PrivateKey caPrivateKey = ESTTestUtils.readPemPrivateKey(
            ESTServerUtils.makeRelativeToServerHome("/extCA/private/cakey.pem"), "ECDSA"
        );


        Object[] bogusCA = bogusCAGenerator();


        //
        // Make client certificate that the server should accept, create the key.
        //

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();

        //
        // Subject DN
        //
        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.CN, "Bunyip Bluegum");
        builder.addRDN(BCStyle.O, "Pudding Protectors");
        builder.addRDN(BCStyle.L, "Victoria");

        X500Name name = builder.build();

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign
            | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
            | KeyUsage.dataEncipherment | KeyUsage.cRLSign);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);


        X509Certificate clientTLSCert = ESTTestUtils.createASignedCert("SHA256WITHECDSA",
            name,
            SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
            new X500Name(((X509Certificate)bogusCA[1]).getSubjectDN().getName()),
            ((PrivateKey)bogusCA[0]),
            1, purposes, keyUsage
        );


        System.out.println(clientTLSCert.toString());


        //
        // Make keystore for client JSSE client auth.
        //
        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null);

        char[] clientKeyStorePass = "tstpass".toCharArray();

        clientKeyStore.setKeyEntry(
            "estuser", // This is hardcoded into the test server.
            originalKeyPair.getPrivate(), clientKeyStorePass,
            new Certificate[]{
                //  ESTTestUtils.toJavaX509Certificate(caCert),
                clientTLSCert
            });

        clientKeyStore.store(new ByteArrayOutputStream(), clientKeyStorePass);


        //
        // Keypair for CSR we wish to enrole.
        //


        kpg.initialize(ecGenSpec);
        KeyPair enrollmentPair = kpg.generateKeyPair();


        ESTTestUtils.ensureProvider();
        final ESTServerUtils.ServerInstance serverInstance = startDefaultServerTLSAndBasicAuth(0, false);
        try
        {

            //
            // Set server trust anchor so client can validate server.
            //

            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            sfcb.withKeyManagerFactory(JcaJceUtils.createKeyManagerFactory(KeyManagerFactory.getDefaultAlgorithm(), null, clientKeyStore, clientKeyStorePass));


            ESTService est = new JcaESTServiceBuilder(
                "https://localhost:8443/.well-known/est/", sfcb.build()
            ).build();


//            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/", Collections.singleton(ta))
//                .withClientKeystore(clientKeyStore, clientKeyStorePass)
//                .build();


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            try
            {
                EnrollmentResponse enr = est.simpleEnroll(
                    false,
                    csr,
                    new HttpAuth("estreal", "estuser", "estpwd".toCharArray(), new SecureRandom(), new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()));
            }
            catch (Exception ex)
            {
                Assert.assertEquals("Only ESTException", ex.getClass(), ESTException.class);

                // NB: My assumption is that it depends on how the server hangs up
                // but we either get a SSL handshake exception or a Socket exception.
                // TODO might be a race.
                Assert.assertTrue("Either SocketException or SSLHandshakeException", (ex.getCause() instanceof SocketException || ex.getCause() instanceof SSLHandshakeException));
            }


        }
        finally
        {
            serverInstance.getServer().stop_server();
        }
    }


    /**
     * Test enrollment using TLS do do the client authentication.
     * In this test we are going to use the BC API to generate a client certificate that the server will accept.
     *
     * @throws Exception
     */
    @Test
    public void testEnrollUsingTLSClientAuthAndBasicAuth()
        throws Exception
    {
        ESTTestUtils.ensureProvider();

        X509CertificateHolder caCert = ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/extCA/cacert.crt")
        );

        PrivateKey caPrivateKey = ESTTestUtils.readPemPrivateKey(
            ESTServerUtils.makeRelativeToServerHome("/extCA/private/cakey.pem"), "ECDSA"
        );

        //
        // Make client certificate that the server should accept, create the key.
        //

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();

        //
        // Subject DN
        //
        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.CN, "Bunyip Bluegum");
        builder.addRDN(BCStyle.O, "Pudding Protectors");
        builder.addRDN(BCStyle.L, "Victoria");

        X500Name name = builder.build();

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign
            | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
            | KeyUsage.dataEncipherment | KeyUsage.cRLSign);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);


        X509Certificate clientTLSCert = ESTTestUtils.createASignedCert("SHA256WITHECDSA",
            name,
            SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
            caCert.getSubject(),
            caPrivateKey,
            1, purposes, keyUsage
        );


        //
        // Make keystore for client JSSE client auth.
        //
        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null);

        char[] clientKeyStorePass = "tstpass".toCharArray();

        clientKeyStore.setKeyEntry(
            "estuser", // This is hardcoded into the test server.
            originalKeyPair.getPrivate(), clientKeyStorePass,
            new Certificate[]{
                //  ESTTestUtils.toJavaX509Certificate(caCert),
                clientTLSCert
            });

        clientKeyStore.store(new ByteArrayOutputStream(), clientKeyStorePass);


        //
        // Keypair for CSR we wish to enrole.
        //


        kpg.initialize(ecGenSpec);
        KeyPair enrollmentPair = kpg.generateKeyPair();


        ESTTestUtils.ensureProvider();
        final ESTServerUtils.ServerInstance serverInstance = startDefaultServerTLSAndBasicAuth(0, false);
        try
        {

            //
            // Set server trust anchor so client can validate server.
            //


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            sfcb.withKeyManagerFactory(JcaJceUtils.createKeyManagerFactory(KeyManagerFactory.getDefaultAlgorithm(), null, clientKeyStore, clientKeyStorePass));


            ESTService est = new JcaESTServiceBuilder(
                "https://localhost:8443/.well-known/est/", sfcb.build()
            ).build();


            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            EnrollmentResponse enr = est.simpleEnroll(
                false,
                csr,
                new JcaHttpAuthBuilder("estreal", "estuser", "estpwd".toCharArray())
                    .setNonceGenerator(new SecureRandom()).setProvider("BC").build());

            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());

        }
        finally
        {
            serverInstance.getServer().stop_server();
        }
    }


    /**
     * Test enrollment using TLS do do the client authentication.
     * In this test we are going to use the BC API to generate a client certificate that the server will accept.
     * This test uses the Bouncycastle SSL provider as it gives access to RFC5929 Channel Bindings.
     *
     * @throws Exception
     */
    @Test()
    @Ignore("Possible race condition.")
    public void testEnrollUsingTLSClientAuthAndPOP()
        throws Exception
    {

        ESTTestUtils.ensureProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        ESTTestUtils.ensureProvider();


        X509CertificateHolder caCert = ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/extCA/cacert.crt")
        );

        PrivateKey caPrivateKey = ESTTestUtils.readPemPrivateKey(
            ESTServerUtils.makeRelativeToServerHome("/extCA/private/cakey.pem"), "ECDSA"
        );

        //
        // Make client certificate that the server should accept, create the key.
        //

        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair originalKeyPair = kpg.generateKeyPair();

        //
        // Subject DN
        //
        X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.CN, "Bunyip Bluegum");
        builder.addRDN(BCStyle.O, "Pudding Protectors");
        builder.addRDN(BCStyle.L, "Victoria");

        X500Name name = builder.build();

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign
            | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
            | KeyUsage.dataEncipherment | KeyUsage.cRLSign);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);


        X509Certificate clientTLSCert = ESTTestUtils.createASignedCert("SHA256WITHECDSA",
            name,
            SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
            caCert.getSubject(),
            caPrivateKey,
            1, purposes, keyUsage
        );


        //
        // Make keystore for client JSSE client auth.
        //
        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null);

        char[] clientKeyStorePass = "tstpass".toCharArray();

        clientKeyStore.setKeyEntry(
            "estuser", // This is hardcoded into the test server.
            originalKeyPair.getPrivate(), clientKeyStorePass,
            new Certificate[]{
                //  ESTTestUtils.toJavaX509Certificate(caCert),
                clientTLSCert
            });

        clientKeyStore.store(new ByteArrayOutputStream(), clientKeyStorePass);

        //
        // Keypair for CSR we wish to enroll.
        //

        kpg.initialize(ecGenSpec);
        KeyPair enrollmentPair = kpg.generateKeyPair();


        ESTTestUtils.ensureProvider();
        final ESTServerUtils.ServerInstance serverInstance = startDefaultServerTLSAndBasicAuth(0, true);
        try
        {
            //
            // Set server trust anchor so client can validate server.
            //

            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);

            ChannelBindingProvider bcChannelBindingProvider = new BCChannelBindingProvider();


            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            sfcb.withKeyManagerFactory(JcaJceUtils.createKeyManagerFactory("X509", null, clientKeyStore, clientKeyStorePass))
                .withTLSProvider(BouncyCastleJsseProvider.PROVIDER_NAME)
                .withTLSVersion("TLS");


            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/", sfcb.build())

                .withChannelBindingProvider(bcChannelBindingProvider)

                .addCipherSuites(new String[]{
                    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                    "TLS_ECDHE_RSA_WITH_NULL_SHA",
                    "TLS_RSA_WITH_AES_128_CCM",
                    "TLS_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                    //  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
                    "TLS_RSA_WITH_AES_256_CBC_SHA256",
                    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
                    "TLS_RSA_WITH_AES_256_CCM_8",
                    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
                    "TLS_RSA_WITH_NULL_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_CBC_SHA256",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_CCM",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                    "TLS_DHE_RSA_WITH_AES_256_CCM_8",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
                    "TLS_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_DHE_RSA_WITH_AES_128_CCM_8",
                    "TLS_RSA_WITH_NULL_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                    "TLS_RSA_WITH_AES_128_CCM_8",
                    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                    "TLS_DHE_RSA_WITH_AES_256_CCM",
                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_DHE_RSA_WITH_AES_128_CCM",
                    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"})
                .build();

            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate());

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //
            EnrollmentResponse enr = est.simpleEnrollPoP(
                false,
                pkcs10Builder,
                contentSigner,
                new JcaHttpAuthBuilder("estreal", "estuser", "estpwd".toCharArray()).setProvider("BC").setNonceGenerator(new SecureRandom()).build());


            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            //
            // Other aspects of CSR testing covered elsewhere
            //

            System.out.println(ESTTestUtils.toJavaX509Certificate(enrolled));

        }
        finally
        {
            serverInstance.getServer().stop_server();
        }
    }

    @Test()
    public void testResponseWith401AndNoAuth()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n\n");
        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());

            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr, null);
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
            }

        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith400()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 400 Bad Request\n" +
            "Status: 400 Bad Request\n" +
            "Content-Length: 0\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());

            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

//            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
//                "https://localhost:" + port + "/.well-known/est/", ESTTestUtils.toTrustAnchor(
//                ESTTestUtils.readPemCertificate(
//                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
//                )));

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr, null);
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertEquals("", 400, ((ESTException)t).getStatusCode());
            }

        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }

    @Test()
    public void testResponseWith401BAndBadQOP()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest qop=\"invalid\", realm=\"estrealm\", nonce=\"1487704890\", algorithm=\"md5\"\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());


            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("'invalid'"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }

    @Test()
    public void testResponseWith401UknownValueInHeader()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest qop=\"invalid\", realm=\"estrealm\", nonce=\"1487704890\", algorithm=\"md5\", dummy=\"value\"\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("'dummy'"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401QpopEmpty()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest qop=\"\", realm=\"estrealm\", nonce=\"1487704890\", algorithm=\"md5\"\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("value is empty"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401BadMode()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Banana qop=\"\", realm=\"estrealm\", nonce=\"1487704890\", algorithm=\"md5\"\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());


            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("banana"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401AndNoWWWHeader()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());


            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("no WWW-Authenticate"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401AndBadAlgorithm()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest qop=\"auth\", realm=\"estrealm\", nonce=\"1487706836\", algorithm=\"token\"\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());


            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("digest algorithm unknown"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401NullNonce()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest qop=\"auth\", realm=\"estrealm\", nonce=\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("Expecting start quote"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401NullRealm()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest qop=\"auth\", realm=, nonce=\"1234\"\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("Expecting start quote"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith401NullQop()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 401 Unauthorized\n" +
            "Status: 401 Unauthorized\n" +
            "Content-Length: 0\n" +
            "WWW-Authenticate: Digest realm=\"estrealm\", nonce=\"1487778654\", qop=\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));


            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());


            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("Expecting start quote"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseWith202NoRetryHeader()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 202 Accepted\n" +
            "Status: 202 Accepted\n" +
            "Content-Length: 0\n\n");
        pw.flush();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime256v1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecGenSpec, new SecureRandom());
            KeyPair enrollmentPair = kpg.generateKeyPair();


            TrustAnchor ta = new TrustAnchor(
                ESTTestUtils.toJavaX509Certificate(
                    ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )
                ), null);


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Test"),
                enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            //
            // Even though we are using TLS we still need to use an HTTP auth.
            //

            int port = res.open(responseData.toByteArray());
            JcaJceSocketFactoryCreatorBuilder sfcb = new JcaJceSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
                "https://localhost:" + port + "/.well-known/est/", sfcb.build());

            builder.addCipherSuites(res.getSupportedCipherSuites());


            try
            {
                EnrollmentResponse resp = builder.build().simpleEnroll(false, csr,
                    new HttpAuth(
                        "estrealm",
                        "estuser",
                        "estpwd".toCharArray(),
                        new SecureRandom(),
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                );
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertTrue("", t.getMessage().contains("not Retry-After header"));
            }
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    public static void main(String[] args)
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        runTest(new TestEnroll());
    }

}
