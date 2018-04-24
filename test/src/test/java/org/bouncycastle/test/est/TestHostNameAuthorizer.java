package org.bouncycastle.test.est;


import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

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
                .withHostNameAuthorizer(new JsseDefaultHostnameAuthorizer(null))
                .addCipherSuites(res.getSupportedCipherSuites())
                .withTLSVersion("TLSv1.2");
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

        Assert.assertTrue("Common Name match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("cisco.com", cert));
    }


    @Test
    public void testCNMismatch_1()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_wc.pem")));

        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark", cert));
    }


    // 192.168.1.50

    @Test
    public void testCNIPMismatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_ip.pem")));

        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("127.0.0.1", cert));
    }

    @Test
    public void testWCMismatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_ip.pem")));

        Assert.assertFalse("Not match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
    }

    @Test
    public void testSANMatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_match.pem")));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("localhost.cisco.com", cert));
    }


    @Test
    public void testSANMatchIP()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_match_ip.pem")));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("192.168.51.140", cert));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("127.0.0.1", cert));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("10.0.0.1", cert));
    }

    @Test
    public void testSANMatchWC()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_wc.pem")));
        Assert.assertTrue("Match", new JsseDefaultHostnameAuthorizer(null).verify("roundhouse.yahoo.com", cert));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("aardvark.cisco.com", cert));
    }

    @Test
    public void testSANMismatchIP()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_ip.pem")));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("localhost.me", cert));
    }


    @Test
    public void testSANMismatchWC()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_wc.pem")));
        Assert.assertFalse("Not Match", new JsseDefaultHostnameAuthorizer(null).verify("localhost.me", cert));
    }
}
