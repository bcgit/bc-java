package org.bouncycastle.test.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.est.AttrOrOID;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;


public class TestGetCSRAttrs
    extends SimpleTest
{

    public String getName()
    {
        return "TestGetCSRAttrs";
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
        config.estTRUSTEDCerts = ESTServerUtils.makeRelativeToServerHome("trustedcerts.crt").getCanonicalPath();
        config.estCACERTSResp = ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt").getCanonicalPath();

        //
        // Mock up some Attributes, this not a real attribute.!
        //
        config.estCSRAttr = Base64.toBase64String(new CsrAttrs(new AttrOrOID(new ASN1ObjectIdentifier("1.2.3.4"))).getEncoded());

        return ESTServerUtils.startServer(config);

    }


    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestGetCSRAttrs.class);
    }


    /**
     * Test the fetching of CSRAttributes.
     * This test confirms it is possible to fetch attributes and that we get an attribute back.
     * Variation on authentication is verified in other tests.
     *
     * @throws Exception
     */
    @Test
    public void testFetchCSRAttributes()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        X509CertificateHolder[] theirCAs = null;
        ESTServerUtils.ServerInstance serverInstance = null;
        try
        {
            serverInstance = startDefaultServer();


            ESTService est = new JsseESTServiceBuilder(
                "localhost:8443",
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null)
            ).build();

            CSRRequestResponse csrRequestResponse = est.getCSRAttributes();
            Assert.assertEquals(1, csrRequestResponse.getAttributesResponse().getRequirements().size());
            Assert.assertTrue("Must have: ",
                csrRequestResponse.getAttributesResponse().hasRequirement(new ASN1ObjectIdentifier("1.2.3.4")));
        }
        finally
        {
            if (serverInstance != null)
            {
                serverInstance.getServer().stop_server();
            }
        }

    }


    @Test()
    public void testResponseWithNoCSRAttributes()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs Content-Transfer-Encoding: base64\n" +
            "Content-Length: 0\n\n");

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
                "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));

            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();


            CSRRequestResponse resp = est.getCSRAttributes();

            Assert.assertFalse("No response expected", resp.hasAttributesResponse());

            try
            {
                resp.getAttributesResponse();
                Assert.fail("Must throw exception.");
            }
            catch (Throwable t)
            {
                Assert.assertEquals("", IllegalStateException.class, t.getClass());
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
    public void testResponseWithNoCSRAttributes202()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 204 No Content\n" +
            "Status: 204 No Content\n" +
            "Content-Type: application/csrattrs Content-Transfer-Encoding: base64\n" +
            "Content-Length: 0\n\n");

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
                "localhost:" + port , JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));

            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();


            CSRRequestResponse resp = est.getCSRAttributes();

            Assert.assertFalse("No response expected", resp.hasAttributesResponse());

            try
            {
                resp.getAttributesResponse();
                Assert.fail("Must throw exception.");
            }
            catch (Throwable t)
            {
                Assert.assertEquals("", IllegalStateException.class, t.getClass());
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
    public void testResponseWithNoCSRAttributes404()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 404 Not Found\n" +
            "Status: 404 Not Found\n" +
            "Content-Type: application/csrattrs Content-Transfer-Encoding: base64\n" +
            "Content-Length: 0\n\n");

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
                "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));

            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();


            CSRRequestResponse resp = est.getCSRAttributes();

            Assert.assertFalse("No response expected", resp.hasAttributesResponse());

            try
            {
                resp.getAttributesResponse();
                Assert.fail("Must throw exception.");
            }
            catch (Throwable t)
            {
                Assert.assertEquals("", IllegalStateException.class, t.getClass());
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

//    @Test()
//    public void testResponseWithLongAttribute()
//        throws Exception
//    {
//
//
////        byte[] b = Base64.decode("MIID/AYHKwYBAQEBFgYJKoZIhvcNAQcBMYID5BOCA+AgMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzN\n" +
////                "DU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzND\n" +
////                "U2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU\n" +
////                "2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2\n" +
////                "Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2N\n" +
////                "zg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaNTU1NTc3NzczMzMzMzMzM1pXWFkxMmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2eHl6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5emFiY2RlZmdoaWprbG1ub3Bxcn\n" +
////                "N0dXZ4eXowOTg3NjU0MzIxYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5emFiY2RlZmdoaWprbG1ub3BxcnN0dXZ4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2eHl6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5ejA5ODc2NTQzMjExMjM0NTY3ODkwQUJDREVGR0h\n" +
////                "JSktMTU5PUFFSUw==\n");
////
////
////        ASN1InputStream ain = new ASN1InputStream(b);
////        ASN1Sequence seq = (ASN1Sequence)ain.readObject();
////
////        System.out.println(ASN1Dump.dumpAsString(seq,true));
////
////        CSRAttributesResponse response = new CSRAttributesResponse(CsrAttrs.getInstance(seq));
//
//
////        ESTTestUtils.ensureProvider();
////        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();
////
////        PrintWriter pw = new PrintWriter(responseData);
////        pw.print("HTTP/1.1 200 OK\n" +
////                "Status: 200 OK\n" +
////                "Content-Type: application/csrattrs\n" +
////                "Content-Transfer-Encoding: base64\n" +
////                "Content-Length: 1368\n\n" +
////                "MIID/AYHKwYBAQEBFgYJKoZIhvcNAQcBMYID5BOCA+AgMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzN\n" +
////                "DU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzND\n" +
////                "U2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU\n" +
////                "2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2\n" +
////                "Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2N\n" +
////                "zg5MEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaNTU1NTc3NzczMzMzMzMzM1pXWFkxMmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2eHl6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5emFiY2RlZmdoaWprbG1ub3Bxcn\n" +
////                "N0dXZ4eXowOTg3NjU0MzIxYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5emFiY2RlZmdoaWprbG1ub3BxcnN0dXZ4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2eHl6YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnh5ejA5ODc2NTQzMjExMjM0NTY3ODkwQUJDREVGR0h\n" +
////                "JSktMTU5PUFFSUw==\n");
////
////        pw.flush();
////
////
////        //
////        // Test content length enforcement.
////        // Fail when content-length = read limit.
////        //
////        HttpResponder res = new HttpResponder();
////        try
////        {
////            int port = res.open(responseData.toByteArray());
////            JcaESTServiceBuilder builder = new JcaESTServiceBuilder(
////                    "localhost:" + port + "/.well-known/est/",ESTTestUtils.toTrustAnchor(
////                    ESTTestUtils.readPemCertificate(
////                            ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
////                    )));
////
////            builder.addCipherSuites(res.getSupportedCipherSuites());
////            ESTService est = builder.build();
////
////
////            CSRRequestResponse resp = est.getCSRAttributes();
////
////            Assert.assertFalse("No response expected",resp.hasAttributesResponse());
////
////            try {
////                resp.getAttributesResponse();
////                Assert.fail("Must throw exception.");
////            } catch (Throwable t) {
////                Assert.assertEquals("",IllegalStateException.class,t.getClass());
////            }
////
////        }
////        catch (Exception ex)
////        {
////            ex.printStackTrace();
////        }
////        finally
////        {
////            res.close();
////        }
////
////        res.getFinished().await(5, TimeUnit.SECONDS);
//
//    }


    @Test()
    public void testResponseWithInvalidResponse()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 31\n\n" +
            "THIS IS A TEST OF INVALID DATA.\n");

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
                "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));


            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();


            CSRRequestResponse resp = est.getCSRAttributes();

            Assert.assertFalse("No response expected", resp.hasAttributesResponse());

            try
            {
                resp.getAttributesResponse();
                Assert.fail("Must throw exception.");
            }
            catch (Throwable t)
            {
                Assert.assertTrue(t.getMessage().contains("Decoding CACerts"));
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
    public void testResponseWithShortContentLength()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 14\n\n" +
            "MAkGBysGAQEBARY=\n");

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
                "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));

            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();

            try
            {
                CSRRequestResponse resp = est.getCSRAttributes();
                Assert.fail("Must throw exception.");
            }
            catch (Exception t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertEquals("Cause must be IOException", t.getCause().getClass(), IOException.class);
                Assert.assertTrue(t.getMessage().contains("extra content in pipe"));
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
    public void testResponseWithBrokenBase64()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 36\n\n" +
            "MBQGBysGAQEBARYGCSqGSIb3DQEHAQpppp==\n");

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
                "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));

            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();

            try
            {
                CSRRequestResponse resp = est.getCSRAttributes();
                Assert.fail("Must throw exception.");
            }
            catch (Throwable t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertEquals("Cause must be IOException", t.getCause().getClass(), IOException.class);
                Assert.assertTrue(t.getMessage().contains("extra content in pipe"));
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
    public void testResponseWithBrokenBase64_3113()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 24\n\n" +
            "MAkGBysGAQEBARY=\n");

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
                "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null));

            builder.addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();

            try
            {
                CSRRequestResponse resp = est.getCSRAttributes();
                Assert.fail("Must throw exception.");
            }
            catch (Throwable t)
            {
                Assert.assertEquals("Must be ESTException", t.getClass(), ESTException.class);
                Assert.assertEquals("Cause must be IOException", t.getCause().getClass(), IOException.class);
                Assert.assertTrue(t.getMessage().contains("closed before limit"));
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

    @Test
    public void testFetchCSRAttrWithTimeout()
        throws Exception
    {
        ESTTestUtils.ensureProvider();

        HttpResponder res = new HttpResponder();


        int port = res.open(null);


        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));

        builder.addCipherSuites(res.getSupportedCipherSuites()).withTimeout(500);

        ESTService est = builder.build();


        try
        {
            CSRRequestResponse csrRequestResponse = est.getCSRAttributes();
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


    @Test
    public void testFetchCSRWithLabel()
        throws Exception
    {
        ESTTestUtils.ensureProvider();

        ArrayList<String> lines = new ArrayList<String>();
        HttpResponder res = new HttpResponder(lines);

        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 17\n\n" +
            "MAkGBysGAQEBARY=\n");

        pw.flush();


        int port = res.open(responseData.toByteArray());

        JsseESTServiceBuilder builder = new JsseESTServiceBuilder(
            "localhost:" + port, JcaJceUtils.getCertPathTrustManager(
            ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
            )), null));

        builder.addCipherSuites(res.getSupportedCipherSuites());

        builder.withLabel("the_label");

        ESTService est = builder.build();


        try
        {
            CSRRequestResponse csrRequestResponse = est.getCSRAttributes();
            Assert.assertTrue(lines.get(0).contains("/.well-known/est/the_label/csrattrs"));
        }
        catch (Exception ex)
        {

            // Not tested here!
//            Assert.assertEquals("", ESTException.class, ex.getClass());
//            Assert.assertEquals("", SocketTimeoutException.class, ex.getCause().getClass());

        }
        finally
        {
            res.close();
            res.getFinished().await(5, TimeUnit.SECONDS);
        }


    }


    public static void main(String[] args)
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        runTest(new TestGetCSRAttrs());
    }
}
