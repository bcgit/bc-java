package org.bouncycastle.pkix.est;

import java.io.FileReader;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.Collections;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.esttst.ESTServerUtils;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;


public class TestCACertsFetch
        extends SimpleTest {

    public String getName() {
        return "TestCACertsFetch";
    }

    public void performTest()
            throws Exception {
        ESTTestUtils.runJUnit(TestCACertsFetch.class);
    }

    private ESTServerUtils.ServerInstance startDefaultServer()
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
            throws Exception {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try {
            serverInstance = startDefaultServer();

            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/").build();
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(true).getStore());

            FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
            PemReader reader = new PemReader(fr);
            X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
            reader.close();
            fr.close();

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

        } finally {
            if (serverInstance != null) {
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
            throws Exception {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try {
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
            X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts(false).getStore());

            // We expect the bootstrap authorizer to not be called.

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);

        } finally {
            if (serverInstance != null) {
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
            throws Exception {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;

        final ESTServerUtils.ServerInstance serverInstance = startDefaultServer();
        try {

            ESTService est = new JcaESTServiceBuilder("https://localhost:8443/.well-known/est/").build();
            ESTService.CACertsResponse caCertsResponse = est.getCACerts(true); //<= Accept any certs tendered by the server.

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

            CertPath cp = cf.generateCertPath(ESTTestUtils.toCertList(caCertsResponse.getSession().getPeerCertificates()));
            CertPathValidator v = CertPathValidator.getInstance("PKIX", "BC");

            PKIXParameters pkixParameters = new PKIXParameters(ESTTestUtils.toTrustAnchor(expectedCACert));
            pkixParameters.setRevocationEnabled(false);

            v.validate(cp, pkixParameters); // <= Throws exception if the path does not validate.


        } finally {
            if (serverInstance != null) {
                serverInstance.getServer().stop_server();
            }
        }

    }


    public static void main(String[] args)
            throws Exception {
        ESTTestUtils.ensureProvider();
        runTest(new TestCACertsFetch());
    }
}
