package org.bouncycastle.pkix.est;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.esttst.ESTServerUtils;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;


public class TestCACertsFetch
        extends SimpleTest
{

    public String getName()
    {
        return "TestCACertsFetch";
    }

    public void performTest()
            throws Exception
    {
        ESTTestUtils.runJUnit(TestCACertsFetch.class);
    }

    private ESTServerUtils.ServerInstance startDefaultServer()
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

        return ESTServerUtils.startServer(config);

    }


    /**
     * Test Fetch CA certs without doing any SSL TLS verification.
     * This is just a catch all to prove we can get some certificates back.
     * Do not use this as an example of how to do it in the world, you need
     * to make a conscious decision about accepting the certificates tended
     * as part of the TLS handshake. See testFetchCaCertsWithBogusTrustAnchor()
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCerts()
            throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServer();

            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/").build();
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts().getStore());

            FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
            PemReader reader = new PemReader(fr);
            X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
            reader.close();
            fr.close();

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

        } finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }

    }


    /**
     * Fetch CA certs with a bogus trust anchor.
     * Expect local library to fail.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsWithBogusTrustAnchor()
            throws Exception
    {


        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServer();


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

            X509Certificate bogusCA = ESTTestUtils.createSelfsignedCert("SHA256WITHECDSA",
                    name,
                    SubjectPublicKeyInfo.getInstance(originalKeyPair.getPublic().getEncoded()),
                    originalKeyPair.getPrivate(),
                    1
            );


            //
            // Use the trust anchor.
            //

            TrustAnchor ta = new TrustAnchor(bogusCA, null);
            ESTService est =
                    new JcaESTServiceBuilder(
                            "https://localhost:8443/.well-known/est/",
                            Collections.singleton(ta)).build();


            //
            // Call expecting failure.
            //
            try
            {
                X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts().getStore());
                Assert.fail("Bogus CA must not validate the server.!");
            } catch (Exception ex)
            {
                Assert.assertEquals("Only ESTException", ex.getClass(), ESTException.class);
                Assert.assertEquals("Cause must be SSLHandshakeException", ex.getCause().getClass(), SSLHandshakeException.class);
            }


        } finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }

    }


    /**
     * Fetch CA certs relying on TLS to validate the server by specifying a trust anchor.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsWithTrustAnchor()
            throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServer();

            //
            // Load the certificate that will become the trust anchor.
            //
            FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
            PemReader reader = new PemReader(fr);
            X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
            reader.close();
            fr.close();


            //
            // Specify the trust anchor.
            //
            TrustAnchor ta = new TrustAnchor(ESTTestUtils.toJavaX509Certificate(fromFile), null);

            ESTService est =
                    new JcaESTServiceBuilder(
                            "https://localhost:8443/.well-known/est/",
                            Collections.singleton(ta)).build();


            // Make the call. NB tlsAcceptAny is false.
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts().getStore());

            // We expect the bootstrap authorizer to not be called.

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

        } finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }

    }


    /**
     * This exercises the concept of bootstrapping as per RFC 7030.
     *
     * We fetch the CA certs from the server using a TLS layer that will accept any certificate tendered by the server.
     * In this situation some sort of out of band validation is expected for example, ask the user if they wish to proceed.
     *
     * This test will fetch the CA certs and use the CertPath api to validate that the CA returned is as expected and
     * it will use the CertPath API to validate the certificates tendered during the TLS handshake by the server.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsChecksResponseUsingCertpath()
            throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;

        final ESTServerUtils.ServerInstance serverInstance = startDefaultServer();
        try
        {

            // Note the constructor without TrustAnchors.
            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/").build();
            ESTService.CACertsResponse caCertsResponse = est.getCACerts(); //<= Accept any certs tendered by the server.

            Assert.assertEquals("Returned ca certs should be 1", ESTService.storeToArray(caCertsResponse.getStore()).length, 1);


            //
            // This is more part of the test, we are checking that the CA cert returned is what we expect.
            // We will later use the expectedCACert to validate the certificates tendered as part of TLS negotiation.
            //
            X509CertificateHolder expectedCACert;
            {
                X509CertificateHolder[] _caCerts = ESTService.storeToArray(caCertsResponse.getStore());

                FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
                PemReader reader = new PemReader(fr);
                expectedCACert = new X509CertificateHolder(reader.readPemObject().getContent());
                reader.close();
                fr.close();

                assert _caCerts.length == 1;
                assert expectedCACert.equals(_caCerts[0]);
            }

            //
            // Use CertPath api to validate tls certs tended by the server expected against the CA.
            //
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            CertPath cp = cf.generateCertPath(ESTTestUtils.toCertList(((SSLSession) caCertsResponse.getSession()).getPeerCertificates()));
            CertPathValidator v = CertPathValidator.getInstance("PKIX", "BC");

            PKIXParameters pkixParameters = new PKIXParameters(ESTTestUtils.toTrustAnchor(expectedCACert));
            pkixParameters.setRevocationEnabled(false);

            v.validate(cp, pkixParameters); // <= Throws exception if the path does not validate.


        } finally
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
        runTest(new TestCACertsFetch());
    }
}
