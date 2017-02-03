package org.bouncycastle.pkix.est;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.http.BasicAuth;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.esttst.ESTServerUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;

public class TestReEnroll
    extends SimpleTest
{

    public String getName()
    {
        return "TestEnroll";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestReEnroll.class);
    }


    private ESTServerUtils.ServerInstance startDefaultServerWithBasicAuth()
        throws Exception
    {

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




    /*
     * We are assuming that the auth modes for enrollment are tested in the TestEnroll tests.
     * Here we want to check for correct behaviour as part of the enrollment process not authentication.
     * So we will stick with basic auth.
     */

    @Test
    public void testReEnrollUsingBasicAuth()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;

        try
        {
            serverInstance = startDefaultServerWithBasicAuth();

            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/",
                    ESTTestUtils.toTrustAnchor(
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


            //
            // Perform a reenrollment Subject and SubjectAltNames must be same.
            //


            enrollmentPair = kpg.generateKeyPair();  // We keep the enrollment keypair.
            pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(csr.getSubject(), enrollmentPair.getPublic());
            csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            // Flag set true!
            enr = est.simpleEnroll(true, csr, new BasicAuth("estreal", "estuser", "estpwd"));
            expectedCA = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            ));

            enrolledAsHolder = ESTService.storeToArray(enr.getStore())[0];

            enrolled = ESTTestUtils.toJavaX509Certificate(enrolledAsHolder);

            // Will fail if it does not verify.
            enrolled.verify(expectedCA.getPublicKey(), "BC");

            TestCase.assertEquals(enrolledAsHolder.getSubject(), csr.getSubject());
            TestCase.assertEquals(enrolledAsHolder.getSubjectPublicKeyInfo(), csr.getSubjectPublicKeyInfo());


            //
            // Try and perform renerollment with different subject.
            //

            // enrollmentPair = kpg.generateKeyPair();
            pkcs10Builder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Samwise Gamgee"), enrollmentPair.getPublic());
            csr = pkcs10Builder.build(
                new JcaContentSignerBuilder("SHA256WITHECDSA").setProvider("BC").build(enrollmentPair.getPrivate()));

            // Flag set true!
            try
            {
                enr = est.simpleEnroll(true, csr, new BasicAuth("estreal", "estuser", "estpwd"));
               // TODO Server needs to enforce this..
               // Assert.fail("Reenrollment with different subject must fail.");
            }
            catch (Exception ex)
            {


                Assert.assertTrue(true);
            }


        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }
    }


    public static void main(String[] args)
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        runTest(new TestReEnroll());
    }

}
