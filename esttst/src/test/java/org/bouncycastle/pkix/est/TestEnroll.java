package org.bouncycastle.pkix.est;


import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.BasicAuth;
import org.bouncycastle.est.DigestAuth;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.esttst.ESTServerUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;

public class TestEnroll
        extends SimpleTest {

    public String getName() {
        return "TestEnroll";
    }

    public void performTest()
            throws Exception {
        ESTTestUtils.runJUnit(TestEnroll.class);
    }


    private ESTServerUtils.ServerInstance startDefaultServerTLSAndBasicAuth()
            throws Exception {
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
        config.enableCheckPOPtoTLSUID = false;

        //
        // Read in openssl config, and adjust it with the correct path.
        //

        String cnf = ESTTestUtils.readToString(ESTServerUtils.makeRelativeToServerHome("/estExampleCA.cnf"));
        cnf = cnf.replace("= ./estCA", "= " + ESTServerUtils.makeRelativeToServerHome("/estCA").getCanonicalPath());
        config.openSSLConfigFile = cnf;

        return ESTServerUtils.startServer(config);

    }


    private ESTServerUtils.ServerInstance startDefaultServerWithBasicAuth()
            throws Exception {

        final ESTServerUtils.EstServerConfig config = new ESTServerUtils.EstServerConfig();
        config.serverCertPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.serverKeyPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.realm = "estreal";
        config.verbose = true;
        config.tcpPort = 8443;
        config.useBasicAuth = true;
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


    private ESTServerUtils.ServerInstance startDefaultServerWithDigestAuth()
            throws Exception {

        final ESTServerUtils.EstServerConfig config = new ESTServerUtils.EstServerConfig();
        config.serverCertPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.serverKeyPemFile = ESTServerUtils.makeRelativeToServerHome("estCA/private/estservercertandkey.pem").getCanonicalPath();
        config.realm = "estreal";
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
            throws Exception {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;

        try {
            serverInstance = startDefaultServerWithBasicAuth();



            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/")
            .withTlsTrustAnchors(ESTTestUtils.toTrustAnchor(
                    ESTTestUtils.readPemCertificate(
                            ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    ))).build();


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

            ESTService.EnrollmentResponse enr = est.simpleEnroll(false, csr, new BasicAuth("estreal", "estuser", "estpwd"));
            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());


        } finally {
            if (serverInstance != null) {
                serverInstance.getServer().stop_server();
            }
        }
    }


    @Test
    public void testEnrollUsingDigestAuth()
            throws Exception {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try {
            serverInstance = startDefaultServerWithDigestAuth();

            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/")
                    .withTlsTrustAnchors(ESTTestUtils.toTrustAnchor(
                                            ESTTestUtils.readPemCertificate(
                                                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                                            ))).build();

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

            //
            // Use an override realm because while the Cisco server sends back "estreal" it the digest was calculated on "estrealm"
            //
            ESTService.EnrollmentResponse enr = est.simpleEnroll(false, csr, new DigestAuth("estrealm", "estuser", "estpwd"));
            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());
        } finally {
            if (serverInstance != null) {
                serverInstance.getServer().stop_server();
            }
        }
    }


    /**
     * Test enrollment using TLS do do the client authentication.
     *
     * @throws Exception
     */
    @Test
    public void testEnrollUsingTLSClientAuthAndBasicAuthP()
            throws Exception {
        ESTTestUtils.ensureProvider();

        X509CertificateHolder caCert = ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/extCA/cacert.crt")
        );

        PrivateKey caPrivateKey = ESTTestUtils.readPemPrivateKey(
                ESTServerUtils.makeRelativeToServerHome("/extCA/private/cakey.pem"), "ECDSA"
        );

        //
        // Make client certificate the server should accept, create the key.
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
        final ESTServerUtils.ServerInstance serverInstance = startDefaultServerTLSAndBasicAuth();
        try {

            //
            // Set server trust anchor so client can validate server.
            //

            TrustAnchor ta = new TrustAnchor(
                    ESTTestUtils.toJavaX509Certificate(
                            ESTTestUtils.readPemCertificate(
                                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                            )
                    ), null);

            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/")
                    .withClientKeystore(clientKeyStore,clientKeyStorePass)
                    .withTlsTrustAnchors(Collections.singleton(ta))
                    .build();


            PKCS10CertificationRequestBuilder pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"), enrollmentPair.getPublic());

            PKCS10CertificationRequest csr = pkcs10Builder.build(
                    new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            ESTService.EnrollmentResponse enr = est.simpleEnroll(false, csr, new BasicAuth("estreal", "estuser", "estpwd"));

            X509Certificate expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            X509CertificateHolder enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            X509Certificate enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());

        } finally {
            serverInstance.getServer().stop_server();
        }
    }


    public static void main(String[] args)
            throws Exception {
        ESTTestUtils.ensureProvider();
        runTest(new TestEnroll());
    }

}
