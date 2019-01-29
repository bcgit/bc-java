package org.bouncycastle.test.est;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.CACertsResponse;
import org.bouncycastle.est.ESTClient;
import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTRequest;
import org.bouncycastle.est.ESTResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.Source;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.test.est.examples.ExampleUtils;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Ignore;
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
            System.setProperty("org.bouncycastle.debug.est", "all");

//            SSLSocketFactoryCreatorBuilder sfcb = new SSLSockuetFactoryCreatorBuilder();

            ESTService est = new JsseESTServiceBuilder("localhost:8443/", JcaJceUtils.getTrustAllTrustManager()).build();
            CACertsResponse caCertsResponse = est.getCACerts();

            X509CertificateHolder[] caCerts = ESTService.storeToArray(caCertsResponse.getCertificateStore());

            FileReader fr = new FileReader(ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt"));
            PemReader reader = new PemReader(fr);
            X509CertificateHolder fromFile = new X509CertificateHolder(reader.readPemObject().getContent());
            reader.close();
            fr.close();
            Assert.assertFalse("Must not be trusted.", caCertsResponse.isTrusted());
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
     * Test to ensure timeout behavior.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCaCertsWithTimeout()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;

        HttpResponder res = new HttpResponder();


        int port = res.open(null);

        ESTService est = new JsseESTServiceBuilder("localhost:" + port, JcaJceUtils.getTrustAllTrustManager()).withTimeout(500).addCipherSuites(res.getEnabledSuites()).build();

        try
        {
            CACertsResponse caCertsResponse = est.getCACerts();
            Assert.fail("Must time out.");
        }
        catch (Exception ex)
        {

            Assert.assertEquals("", ESTException.class, ex.getClass());
            Assert.assertEquals("", SocketTimeoutException.class, ex.getCause().getClass());

        }
        finally
        {
            res.getFinished().await(5, TimeUnit.SECONDS);
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
                new JsseESTServiceBuilder(
                    "localhost:8443",
                    JcaJceUtils.getCertPathTrustManager(ESTTestUtils.toTrustAnchor(ta), null)).build();


            //
            // Call expecting failure.
            //
            try
            {
                X509CertificateHolder[] caCerts = ESTService.storeToArray(est.getCACerts().getCertificateStore());
                Assert.fail("Bogus CA must not validate the server.!");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("Only ESTException", ex.getClass(), ESTException.class);
                Assert.assertEquals("Cause must be SSLHandshakeException", ex.getCause().getClass(), SSLHandshakeException.class);
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
                new JsseESTServiceBuilder(
                    "localhost:8443",
                    JcaJceUtils.getCertPathTrustManager(ESTTestUtils.toTrustAnchor(ta), null))
                    .build();

            CACertsResponse caCertsResponse = est.getCACerts();
            // Make the call. NB tlsAcceptAny is false.
            X509CertificateHolder[] caCerts = ESTService.storeToArray(caCertsResponse.getCertificateStore());

            // We expect the bootstrap authorizer to not be called.

            Assert.assertEquals("Returned ca certs should be 1", caCerts.length, 1);
            Assert.assertEquals("CA cert did match expected.", fromFile, caCerts[0]);
            Assert.assertTrue("Must be trusted.", caCertsResponse.isTrusted());
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
     * This exercises the concept of bootstrapping as per RFC 7030.
     * <p>
     * We fetch the CA certs from the server using a TLS layer that will accept any certificate tendered by the server.
     * In this situation some sort of out of band validation is expected for example, ask the user if they wish to proceed.
     * <p>
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

            // SSLSocketFactoryCreatorBuilder sfcb = new SSLSocketFactoryCreatorBuilder(JcaJceUtils.getTrustAllTrustManager());

            ESTService est =
                new JsseESTServiceBuilder(
                    "localhost:8443",
                    JcaJceUtils.getTrustAllTrustManager()).build();

//            // Note the constructor without TrustAnchors.
//            ESTService est = new JcaESTServiceBuilder("localhost:8443/.well-known/est/").build();


            CACertsResponse caCertsResponse = est.getCACerts(); //<= Accept any certs tendered by the server.

            Assert.assertEquals("Returned ca certs should be 1", ESTService.storeToArray(caCertsResponse.getCertificateStore()).length, 1);


            //
            // This is more part of the test, we are checking that the CA cert returned is what we expect.
            // We will later use the expectedCACert to validate the certificates tendered as part of TLS negotiation.
            //
            X509CertificateHolder expectedCACert;
            {
                X509CertificateHolder[] _caCerts = ESTService.storeToArray(caCertsResponse.getCertificateStore());

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

            CertPath cp = cf.generateCertPath(ESTTestUtils.toCertList(((SSLSession)caCertsResponse.getSession()).getPeerCertificates()));
            CertPathValidator v = CertPathValidator.getInstance("PKIX", "BC");

            PKIXParameters pkixParameters = new PKIXParameters(ESTTestUtils.toTrustAnchor(expectedCACert));
            pkixParameters.setRevocationEnabled(false);

            v.validate(cp, pkixParameters); // <= Throws exception if the path does not validate.


        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }

    }

    @Test(expected = IllegalStateException.class)
    public void testEmptyCaCertsResponseZeroLength()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\r\n");
        pw.print("Status: 200 OK\r\n");
        pw.print("Content-Type: application/pkcs7-mime\r\n");
        pw.print("Content-Transfer-Encoding: base64\r\n");
        pw.print("Content-Length: 0\r\n");
        pw.print("\r\n");
        pw.flush();


        final ESTResponse response = new ESTResponse(null, new Source()
        {
            public InputStream getInputStream()
                throws IOException
            {
                return new ByteArrayInputStream(responseData.toByteArray());
            }

            public OutputStream getOutputStream()
                throws IOException
            {
                return null;
            }

            public Object getSession()
            {
                return null;
            }

            public Object getTLSUnique()
            {
                return null;
            }

            public boolean isTLSUniqueAvailable()
            {
                return false;
            }

            public void close()
                throws IOException
            {

            }
        });

        ESTServiceBuilder builder = new ESTServiceBuilder("foo.local")
        {
            @Override
            public ESTService build()
            {
                return super.build();
            }
        };

        builder.withClientProvider(new ESTClientProvider()
        {
            public ESTClient makeClient()
                throws ESTException
            {
                return new ESTClient()
                {
                    public ESTResponse doRequest(ESTRequest c)
                        throws IOException
                    {
                        return response;
                    }
                };
            }

            public boolean isTrusted()
            {
                return false;
            }
        });


        ESTService estService = builder.build();
        CACertsResponse resp = estService.getCACerts();
        Assert.assertFalse("Must be false, store is null", resp.hasCertificates());
        resp.getCertificateStore();
    }


    @Test(expected = IllegalStateException.class)
    public void testEmptyCaCertsResponse204()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 204 OK\r\n");
        pw.print("Status: 204 OK\r\n");
        pw.print("Content-Type: application/pkcs7-mime\r\n");
        pw.print("Content-Transfer-Encoding: base64\r\n");

        pw.print("\r\n");
        pw.flush();


        final ESTResponse response = new ESTResponse(null, new Source()
        {
            public InputStream getInputStream()
                throws IOException
            {
                return new ByteArrayInputStream(responseData.toByteArray());
            }

            public OutputStream getOutputStream()
                throws IOException
            {
                return null;
            }

            public Object getSession()
            {
                return null;
            }

            public Object getTLSUnique()
            {
                return null;
            }

            public boolean isTLSUniqueAvailable()
            {
                return false;
            }

            public void close()
                throws IOException
            {

            }
        });

        ESTServiceBuilder builder = new ESTServiceBuilder("foo.local")
        {
            @Override
            public ESTService build()
            {
                return super.build();
            }
        };

        builder.withClientProvider(new ESTClientProvider()
        {
            public ESTClient makeClient()
                throws ESTException
            {
                return new ESTClient()
                {
                    public ESTResponse doRequest(ESTRequest c)
                        throws IOException
                    {
                        return response;
                    }
                };
            }

            public boolean isTrusted()
            {
                return false;
            }
        });


        ESTService estService = builder.build();
        CACertsResponse resp = estService.getCACerts();
        Assert.assertFalse("Must be false, store is null", resp.hasCertificates());
        resp.getCertificateStore();
    }


    @Test()
    public void testEmptyCaCertsResponseTruncated()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 10\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA");

        pw.flush();

        final ESTResponse response = new ESTResponse(null, new Source()
        {
            public InputStream getInputStream()
                throws IOException
            {
                return new ByteArrayInputStream(responseData.toByteArray());
            }

            public OutputStream getOutputStream()
                throws IOException
            {
                return null;
            }

            public Object getSession()
            {
                return null;
            }

            public Object getTLSUnique()
            {
                return null;
            }

            public boolean isTLSUniqueAvailable()
            {
                return false;
            }

            public void close()
                throws IOException
            {

            }
        });

        ESTServiceBuilder builder = new ESTServiceBuilder("foo.local")
        {
            @Override
            public ESTService build()
            {
                return super.build();
            }
        };

        builder.withClientProvider(new ESTClientProvider()
        {
            public ESTClient makeClient()
                throws ESTException
            {
                return new ESTClient()
                {
                    public ESTResponse doRequest(ESTRequest c)
                        throws IOException
                    {
                        return response;
                    }
                };
            }

            public boolean isTrusted()
            {
                return false;
            }
        });


        ESTService estService = builder.build();
        try
        {
            CACertsResponse resp = estService.getCACerts();
            Assert.fail("Must fail on too small content length.");
        }
        catch (Exception ex)
        {
            Assert.assertEquals("Expect EST Exception", ESTException.class, ex.getClass());
            Assert.assertTrue("Expect cause an IOException", ex.getCause() instanceof IOException);
        }

    }


    @Test()
    public void testEmptyCaCertsResponseContentExceedsResponse()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 1000\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA");

        pw.flush();

        final ESTResponse response = new ESTResponse(null, new Source()
        {
            public InputStream getInputStream()
                throws IOException
            {
                return new ByteArrayInputStream(responseData.toByteArray());
            }

            public OutputStream getOutputStream()
                throws IOException
            {
                return null;
            }

            public Object getSession()
            {
                return null;
            }

            public Object getTLSUnique()
            {
                return null;
            }

            public boolean isTLSUniqueAvailable()
            {
                return false;
            }

            public void close()
                throws IOException
            {

            }
        });

        ESTServiceBuilder builder = new ESTServiceBuilder("foo.local")
        {
            @Override
            public ESTService build()
            {
                return super.build();
            }
        };

        builder.withClientProvider(new ESTClientProvider()
        {
            public ESTClient makeClient()
                throws ESTException
            {
                return new ESTClient()
                {
                    public ESTResponse doRequest(ESTRequest c)
                        throws IOException
                    {
                        return response;
                    }
                };
            }

            public boolean isTrusted()
            {
                return false;
            }
        });


        ESTService estService = builder.build();
        try
        {
            estService.getCACerts();
            Assert.fail("Must fail on not reading all content.");
        }
        catch (Exception ex)
        {
            Assert.assertEquals("Must be EST Exception", ESTException.class, ex.getClass());
            Assert.assertEquals("Cause is IO Exception.", IOException.class, IOException.class);
        }
    }

    @Test()
    public void testEmptyCaCertsResponseContentLengthExceedsAbsoluteLimit()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 1000\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());


            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());


            builder.withReadLimit(1000L);
            builder.addCipherSuites(res.getEnabledSuites());

            ESTService est = builder.build();
            try
            {
                est.getCACerts();
                Assert.fail("Must fail.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertEquals("", IOException.class, ex.getCause().getClass());

            }

        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testContentLengthBelowAbsoluteLimit()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());

            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getEnabledSuites());

            ESTService est = builder.build();

            // This must not fail.
            est.getCACerts();

        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseContentLengthInvalid()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: banana\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getSupportedCipherSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, content length = banana");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertEquals("", RuntimeException.class, ex.getCause().getClass());
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseNoContentLengthHeader()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getSupportedCipherSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, no content length header");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertEquals("", IOException.class, ex.getCause().getClass());
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testResponseNegativeContentLength()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: -1\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());

            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getSupportedCipherSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, content length = banana");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertEquals("", IOException.class, ex.getCause().getClass());
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);
    }

    @Test()
    public void testIncorrectContentType()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/octet-stream\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getSupportedCipherSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, incorrect content type.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testMissingContentType()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getSupportedCipherSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, incorrect content type.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertTrue(ex.getMessage().contains("but was not present"));
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testRejectOnTLSv1Establishment()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder().withTlsProtocol("TLSv1");
        try
        {


            int port = res.open(responseData.toByteArray());

            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getSupportedCipherSuites());
            builder.withTLSVersion("TLSv1");

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, incorrect content type.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertEquals("", IOException.class, ex.getCause().getClass());
                Assert.assertTrue(ex.getMessage().contains("must not use TLSv1"));
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testRejectOnNullCipherEstablishment()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        res.setCipherSuites(new String[]{
            "TLS_RSA_WITH_NULL_SHA256",
            "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            "TLS_ECDHE_RSA_WITH_NULL_SHA",
            "SSL_RSA_WITH_NULL_SHA",
            "TLS_ECDH_ECDSA_WITH_NULL_SHA",
            "TLS_ECDH_RSA_WITH_NULL_SHA",
            "TLS_ECDH_anon_WITH_NULL_SHA",
            "SSL_RSA_WITH_NULL_MD5"
        });
        try
        {
            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "127.0.0.1:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530).withHostNameAuthorizer(null);
            builder.addCipherSuites(res.getEnabledSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, incorrect no null ciphers.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertTrue("", ex.getCause() instanceof IOException);
                Assert.assertTrue(ex.getMessage().contains("must not use NULL"));
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testRejectOnAnonCipherEstablishment()
        throws Exception
    {

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        res.setCipherSuites(new String[]{
            "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
            "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
            "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDH_anon_WITH_RC4_128_SHA",
            "SSL_DH_anon_WITH_RC4_128_MD5",
            "SSL_DH_anon_WITH_DES_CBC_SHA",
            "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
        });
        try
        {
            int port = res.open(responseData.toByteArray());

            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "127.0.0.1:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530).withHostNameAuthorizer(null);
            builder.addCipherSuites(res.getEnabledSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, used anon cipher.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertTrue("", ex.getCause() instanceof IOException);
                Assert.assertTrue(ex.getMessage().contains("must not use anon"));
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    @Ignore("JVMs 7,8 etc don't easily support creation of EXPORT cipher suites, so this has been skipped.")
    public void testRejectOnExportCipherEstablishment()
        throws Exception
    {

        ExampleUtils.ensureProvider();
        //
        // We need a self signed certificate using transformations old enough
        // to work with Export suites.
        //

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = ExampleUtils.toJavaX509Certificate(
            ExampleUtils.createSelfsignedCert("SHA1withRSA", new X500Name("CN=127.0.0.1"), SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()), kp.getPrivate(), 1)
        );


        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder().withTlsProtocol("TLSv1").withCreds(cert, kp.getPrivate());
        res.setCipherSuites(new String[]{
            "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
//            "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
//            "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
//            "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
//            "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
        });
        try
        {
            int port = res.open(responseData.toByteArray());


            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "127.0.0.1:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.withTLSVersion("TLSv1");
            builder.withProvider("SunJSSE");


            String[] k = res.getEnabledSuites();
            builder.addCipherSuites(res.getEnabledSuites());

            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, used export cipher.");
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertTrue("Cause is IOException", ex.getCause() instanceof IOException);
                Assert.assertTrue(ex.getMessage().contains("must not use export"));
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testRejectOnDESCipherEstablishment()
        throws Exception
    {

        ExampleUtils.ensureProvider();
        //
        // We need a self signed certificate using transformations old enough
        // to work with Export suites.
        //

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = ExampleUtils.toJavaX509Certificate(
            ExampleUtils.createSelfsignedCert("SHA1withRSA", new X500Name("CN=127.0.0.1"), SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()), kp.getPrivate(), 1)
        );


        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 529\n" +
            "\n" +
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
            "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
            "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
            "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
            "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
            "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
            "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
            "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
            "spOU3zEA\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder().withCreds(cert, kp.getPrivate());
        res.setCipherSuites(new String[]{
            "SSL_RSA_WITH_DES_CBC_SHA",
            "SSL_DHE_RSA_WITH_DES_CBC_SHA",
            "SSL_DHE_DSS_WITH_DES_CBC_SHA",
            "SSL_DH_anon_WITH_DES_CBC_SHA",
            "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
            "TLS_KRB5_WITH_DES_CBC_SHA",
            "TLS_KRB5_WITH_DES_CBC_MD5",
            "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
            "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
        });
        try
        {
            int port = res.open(responseData.toByteArray());

            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "127.0.0.1:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.withReadLimit(530);
            builder.addCipherSuites(res.getEnabledSuites());
            builder.withTLSVersion("TLSv1"); // <- needed to get export suites to work.
            ESTService est = builder.build();

            try
            {
                est.getCACerts();
                Assert.fail("Must fail, used export cipher.");
            }
            catch (Exception ex)
            {
                Assert.assertEquals("EST Exception", ESTException.class, ex.getClass());
                Assert.assertEquals("Cause is IOException", IOException.class, ex.getCause().getClass());
                Assert.assertTrue(ex.getMessage().contains("must not use DES"));
            }
        }
        finally
        {
            res.close();
        }

        res.getFinished().await(5, TimeUnit.SECONDS);

    }


    @Test()
    public void testCertResponseWithCRL()
        throws Exception
    {
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 655\n" +
            "\n" +
            "MIIB3QYJKoZIhvcNAQcCoIIBzjCCAcoCAQExADALBgkqhkiG9w0BBwGgggGwMIIB\n" +
            "rDCCAVKgAwIBAgICLdwwCQYHKoZIzj0EATAXMRUwEwYDVQQDDAxlc3RFeGFtcGxl\n" +
            "Q0EwHhcNMTQwNzA5MTY0NzExWhcNMzMwOTA3MTY0NzExWjAXMRUwEwYDVQQDDAxl\n" +
            "c3RFeGFtcGxlQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATbixdp4YMKGmfj\n" +
            "fF2rzwRQXMX+2YoJvsskqU3qMUAJhfrYvMPo3smPWbE0jftfw+UlsKD3HiHUCOCV\n" +
            "ySHKSfPbo4GOMIGLMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFN0KrHLtKvSyE5OI\n" +
            "c9MAA9sCAbTyMB8GA1UdIwQYMBaAFN0KrHLtKvSyE5OIc9MAA9sCAbTyMDsGA1Ud\n" +
            "EQQ0MDKCCWxvY2FsaG9zdIINaXA2LWxvY2FsaG9zdIcEfwAAAYcQAAAAAAAAAAAA\n" +
            "AAAAAAAAATAJBgcqhkjOPQQBA0kAMEYCIQDNq+Vjoi6mgSqXSLzJ7OVs+RzjGox3\n" +
            "xXttoJ9B7eDjjgIhALpU+OVvyfhDJbHegWC02OX6laPTBNjAf6V8aVOP1rYdoQAx\n" +
            "AA==\n");

        pw.flush();


        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder();
        try
        {

            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();


            CACertsResponse resp = est.getCACerts();


            Assert.assertTrue("Must have CRLS", resp.hasCRLs());
            Assert.assertTrue("Must have Certs", resp.hasCertificates());

            Store<X509CertificateHolder> x509CertificateHolderStore = resp.getCertificateStore();
            Collection<X509CertificateHolder> x509CertificateHolders = x509CertificateHolderStore.getMatches(null);
            Assert.assertTrue(!x509CertificateHolders.isEmpty());

            Store<X509CRLHolder> x509CRLHolderStore = resp.getCrlStore();
            Collection<X509CRLHolder> x509CRLHolders = x509CRLHolderStore.getMatches(null);
            Assert.assertTrue(x509CRLHolders.isEmpty()); // CRL is actually empty.
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
    public void testCertResponseWithLabelApplication()
        throws Exception
    {
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/pkcs7-mime\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 655\n" +
            "\n" +
            "MIIB3QYJKoZIhvcNAQcCoIIBzjCCAcoCAQExADALBgkqhkiG9w0BBwGgggGwMIIB\n" +
            "rDCCAVKgAwIBAgICLdwwCQYHKoZIzj0EATAXMRUwEwYDVQQDDAxlc3RFeGFtcGxl\n" +
            "Q0EwHhcNMTQwNzA5MTY0NzExWhcNMzMwOTA3MTY0NzExWjAXMRUwEwYDVQQDDAxl\n" +
            "c3RFeGFtcGxlQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATbixdp4YMKGmfj\n" +
            "fF2rzwRQXMX+2YoJvsskqU3qMUAJhfrYvMPo3smPWbE0jftfw+UlsKD3HiHUCOCV\n" +
            "ySHKSfPbo4GOMIGLMAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFN0KrHLtKvSyE5OI\n" +
            "c9MAA9sCAbTyMB8GA1UdIwQYMBaAFN0KrHLtKvSyE5OIc9MAA9sCAbTyMDsGA1Ud\n" +
            "EQQ0MDKCCWxvY2FsaG9zdIINaXA2LWxvY2FsaG9zdIcEfwAAAYcQAAAAAAAAAAAA\n" +
            "AAAAAAAAATAJBgcqhkjOPQQBA0kAMEYCIQDNq+Vjoi6mgSqXSLzJ7OVs+RzjGox3\n" +
            "xXttoJ9B7eDjjgIhALpU+OVvyfhDJbHegWC02OX6laPTBNjAf6V8aVOP1rYdoQAx\n" +
            "AA==\n");

        pw.flush();


        final ArrayList<String> lineBuffer = new ArrayList<String>();

        //
        // Test content length enforcement.
        // Fail when content-length = read limit.
        //
        HttpResponder res = new HttpResponder(lineBuffer);
        try
        {

            int port = res.open(responseData.toByteArray());
            JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
                "localhost:" + port, JcaJceUtils.getTrustAllTrustManager());
            builder.addCipherSuites(res.getSupportedCipherSuites());

            builder.withLabel("the_label");

            ESTService est = builder.build();


            CACertsResponse resp = est.getCACerts();

            Assert.assertTrue(lineBuffer.get(0).contains("/.well-known/est/the_label/cacerts"));

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
        runTest(new TestCACertsFetch());
    }
}
