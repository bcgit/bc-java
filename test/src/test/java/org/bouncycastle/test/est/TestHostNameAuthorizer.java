package org.bouncycastle.test.est;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.junit.Assert;
import org.junit.Test;

/**
 * TestHostNameAuthorizer tests the hostname authorizer only. EST related functions
 * are not tested here.
 */
public class TestHostNameAuthorizer
{
    /**
     * name = localhost, dnsName = 127.0.0.1
     * Also tests the host name verifier is indeed called by the client.
     *
     * @throws Exception
     */
    @Test
    public void testMatch()
        throws Exception
    {
        ESTTestUtils.ensureProvider();
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();

        PrintWriter pw = new PrintWriter(responseData);
        pw.print("HTTP/1.1 200 OK\n" +
            "Status: 200 OK\n" +
            "Content-Type: application/csrattrs\n" +
            "Content-Transfer-Encoding: base64\n" +
            "Content-Length: 17\n\n" +
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
                "localtest.me:" + port, JcaJceUtils.getCertPathTrustManager(
                ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                    ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                )), null))
                .withHostNameAuthorizer(new JsseDefaultHostnameAuthorizer())
                .addCipherSuites(res.getSupportedCipherSuites());
            ESTService est = builder.build();

            CSRRequestResponse resp = est.getCSRAttributes();
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


    /*
        The following tests do not attempt to validate the certificates.
        They only test hostname verification behavior.
     */

    @Test
    public void testCNMatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_match_wc.pem")));

        Assert.assertTrue("Common Name match", new JsseDefaultHostnameAuthorizer().verify("aardvark.cisco.com", cert));
        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer().verify("cisco.com", cert));
    }


    @Test
    public void testCNMismatch_1()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_wc.pem")));

        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer().verify("aardvark", cert));
    }


    // 192.168.1.50

    @Test
    public void testCNIPMismatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_ip.pem")));

        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer().verify("127.0.0.1", cert));
    }

    @Test
    public void testWCMismatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_ip.pem")));

        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer().verify("aardvark.cisco.com", cert));
    }

    @Test
    public void testSANMatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_match.pem")));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer().verify("localhost.cisco.com", cert));
    }


    @Test
    public void testSANMatchIP()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_match_ip.pem")));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer().verify("192.168.51.140", cert));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer().verify("127.0.0.1", cert));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer().verify("10.0.0.1", cert));
    }

    @Test
    public void testSANMatchWC()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_wc.pem")));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer().verify("roundhouse.yahoo.com", cert));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer().verify("aardvark.cisco.com", cert));
    }

    @Test
    public void testSANMismatchIP()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_ip.pem")));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer().verify("localhost.me", cert));
    }


    @Test
    public void testSANMismatchWC()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_wc.pem")));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer().verify("localhost.me", cert));
    }

    @Test
    public void testWildcardMatcher() throws Exception {

        Object[][] v = new Object[][]{
         //   {"Too wide a match", "foo.com","*.com",false}, // too wide a match
            {"Exact","a.foo.com","a.foo.com",true},
            {"Left most","abacus.foo.com","*s.foo.com",true}, // Match the left most.
          //  {"Invalid 1","localhost.cisco.com","localhost.*.com",false},
            {"Invalid 2","localhost.cisco.com","localhost.cisco.*",false},
          //  {"Invalid 3","localhost.cisco.com","*.com",false},
            {"Invalid 4","localhost.cisco.com","*.localhost.cisco.com",false},
            {"Invalid 5","localhost.cisco.com","*",false},
            {"Invalid 6","localhost.cisco.com","localhost*.cisco.com",false},
            {"Invalid 7","localhost.cisco.com","*localhost.cisco.com",false},
            {"Invalid 8","localhost.cisco.com","local*host.cisco.com",false},
            {"Invalid 9","localhost.cisco.com","localhost.c*.com",false},
            {"Invalid 10","localhost.cisco.com","localhost.*o.com",false},
            {"Invalid 11","localhost.cisco.com","localhost.c*o.com",false},
            {"Invalid 11","localhost.cisco.com","*..com",false},
        };

        for (Object[] j : v) {
            Assert.assertEquals(j[0].toString(),j[3],JsseDefaultHostnameAuthorizer.testName((String)j[1],(String)j[2]) );
        }
    }

    @Test(expected = IOException.class)
    public void testWildcardPublicSuffix() throws Exception {

        Object[][] v = new Object[][]{

             {"Invalid 3","localhost.cisco.com","*.com",false},

        };

        for (Object[] j : v) {
            Assert.assertEquals(j[0].toString(),j[3],JsseDefaultHostnameAuthorizer.testName((String)j[1],(String)j[2]) );
        }
    }


}
