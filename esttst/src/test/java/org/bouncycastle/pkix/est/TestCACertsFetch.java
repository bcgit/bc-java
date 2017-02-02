package org.bouncycastle.pkix.est;

import java.io.FileReader;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLSession;
import javax.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.RFC7030BootstrapAuthorizer;
import org.bouncycastle.esttst.ESTServerUtils;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;


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
     * as part of the TLS handshake. See testFetchCaCertsWithCallbackAuthorizerChecks()
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

            ESTService est = new ESTServiceBuilder("https://localhost:8443/.well-known/est/").build();
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(null, true));

            FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
            PemReader reader = new PemReader(fr);
            X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
            reader.close();
            fr.close();

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

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
                new ESTServiceBuilder(Collections.singleton(ta), "https://localhost:8443/.well-known/est/").build();


            final AtomicBoolean bsaCalled = new AtomicBoolean(false);
            RFC7030BootstrapAuthorizer<SSLSession> bsa = new RFC7030BootstrapAuthorizer<SSLSession>()
            {
                public void authorise(Store<X509CertificateHolder> caCerts, X509Certificate[] serverCertificates, SSLSession session)
                    throws Exception
                {
                    bsaCalled.set(true);
                }
            };


            // Make the call. NB tlsAcceptAny is false.
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(bsa, false));

            // We expect the bootstrap authorizer to not be called.

            Assert.assertFalse("Bootstrap authorizer should not be called.", bsaCalled.get());
            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

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
     * Fetch CA certificates and verify that the bootstrap authorizer is called.
     * If you are going to use a bootstrap authorizer it means that you do not
     * have local certificates suitable for verifying the server. The intention in the RFC is that
     * users be given the opportunity to accept or deny the certificates based on their own observations.
     * To make this work callers must set the tlsAcceptAny flag to true so that TLS layer accepts
     * any and all certificates tendered by the server.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsWithCallbackAuthorizer()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;

        try
        {
            serverInstance = startDefaultServer();

            final AtomicBoolean bootStrapAuthorizerCalled = new AtomicBoolean(false);

            RFC7030BootstrapAuthorizer<SSLSession> bootstrapAuthorizer = new RFC7030BootstrapAuthorizer<SSLSession>()
            {
                public void authorise(Store<X509CertificateHolder> caCerts, X509Certificate[] serverCertificates, SSLSession sslSession)
                    throws Exception
                {
                    bootStrapAuthorizerCalled.set(true);
                }
            };

            ESTService est = new ESTServiceBuilder("https://localhost:8443/.well-known/est/").build();

            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(bootstrapAuthorizer, true));

            FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
            PemReader reader = new PemReader(fr);
            X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
            reader.close();
            fr.close();

            Assert.assertEquals("Bootstrap authorizer must be called", true, bootStrapAuthorizerCalled.get());
            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

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
     * Fetch CA certificates and verify that the bootstrap authorizer is called.
     * <p>
     * In this instance the bootstrap authorizer fails by throwing an exception.
     * We also check that the certificates tendered as expected.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsWithCallbackAuthorizerDenying()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServer();

            RFC7030BootstrapAuthorizer<SSLSession> bootstrapAuthorizer = new RFC7030BootstrapAuthorizer<SSLSession>()
            {
                public void authorise(Store<X509CertificateHolder> caCerts, X509Certificate[] serverCertificates, SSLSession sslSession)
                    throws Exception
                {

                    throw new RuntimeException("boom");
                }
            };


            ESTService est = new ESTServiceBuilder("https://localhost:8443/.well-known/est/").build();

            try
            {
                X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(bootstrapAuthorizer, true));
                Assert.fail("Bootstrap authorizer exception did not propagate.");
            }
            catch (Throwable t)
            {
                Assert.assertEquals("Wrong exception:", t.getMessage(), "boom");
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

    /**
     * Fetch CA certificates using a bootstrap authorizer that checks that the
     * tendered CA and the certificates tendered as part of the TLS handshake form a
     * path.
     * <p>
     * This uses the CertPath API.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsWithCallbackAuthorizerChecks()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;

        final ESTServerUtils.ServerInstance serverInstance = startDefaultServer();

        final AtomicBoolean bootStrapAuthorizerCalled = new AtomicBoolean(false);
        try
        {

            //
            // Set up a boot strap authorizer that tests the tendered CA and the tls certificates.
            //
            RFC7030BootstrapAuthorizer<SSLSession> bootstrapAuthorizer = new RFC7030BootstrapAuthorizer<SSLSession>()
            {
                public void authorise(Store<X509CertificateHolder> caCerts, X509Certificate[] serverCertificates, SSLSession session)
                    throws Exception
                {
                    // This is just a sanity check due to the default success nature of the Bootstrap authorizer.
                    // We need to be sure this has been called.
                    bootStrapAuthorizerCalled.set(true);

                    //
                    // Test tendered CA cert.
                    //
                    X509CertificateHolder expectedCACert;
                    {
                        X509CertificateHolder[] _caCerts = ESTService.storeToArray(caCerts);

                        FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
                        PemReader reader = new PemReader(fr);
                        expectedCACert = new X509CertificateHolder(reader.readPemObject().getContent());
                        reader.close();
                        fr.close();

                        assert _caCerts.length == 1;
                        assert expectedCACert.equals(_caCerts[0]);
                    }

                    //
                    // Test there is a valid path between the tlsCertificates tendered and the tendered CA cert.
                    // If there is not an exception will be thrown and this will fail.
                    //

                    {

                        assert serverCertificates.length == 2;

                        //
                        // Use CertPath api to validate tls certs against expected CA.
                        //

                        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                        CertPath cp = cf.generateCertPath(ESTTestUtils.toCertList(serverCertificates));
                        CertPathValidator v = CertPathValidator.getInstance("PKIX", "BC");

                        PKIXParameters pkixParameters = new PKIXParameters(ESTTestUtils.toTrustAnchor(expectedCACert));
                        pkixParameters.setRevocationEnabled(false);
                        // PKIXCertPathValidatorResult res = (PKIXCertPathValidatorResult)
                        v.validate(cp, pkixParameters); // <= Throws exception if the path does not validate.
                    }
                }
            };


            ESTService est = new ESTServiceBuilder("https://localhost:8443/.well-known/est/").build();
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(bootstrapAuthorizer, true));

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("Bootstrap authorizer must be called", true, bootStrapAuthorizerCalled.get());

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
        runTest(new TestCACertsFetch());
    }
}
