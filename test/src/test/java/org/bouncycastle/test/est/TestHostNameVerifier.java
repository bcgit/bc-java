package org.bouncycastle.test.est;


import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.jcajce.DefaultHostnameVerifier;
import org.bouncycastle.est.jcajce.JSSEESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.SSLSocketFactoryCreatorBuilder;
import org.junit.Assert;
import org.junit.Test;

/**
 * TestHostNameVerifier tests the hostname verifier only any EST related functions
 * are not tested here.
 */
public class TestHostNameVerifier
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
            SSLSocketFactoryCreatorBuilder sfcb = new SSLSocketFactoryCreatorBuilder(
                JcaJceUtils.getCertPathTrustManager(
                    ESTTestUtils.toTrustAnchor(ESTTestUtils.readPemCertificate(
                        ESTServerUtils.makeRelativeToServerHome("/estCA/cacert.crt")
                    )), null));

            JSSEESTServiceBuilder builder = new JSSEESTServiceBuilder(
                "https://localtest.me:" + port + "/.well-known/est/", sfcb.build())
                .withHostNameAuthorizer(new DefaultHostnameVerifier())
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

        Assert.assertTrue("Common Name match", new DefaultHostnameVerifier().verify("aardvark.cisco.com", cert));
        Assert.assertFalse("Not match", new DefaultHostnameVerifier().verify("cisco.com", cert));
    }


    @Test
    public void testCNMismatch_1()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_wc.pem")));

        Assert.assertFalse("Not match", new DefaultHostnameVerifier().verify("aardvark", cert));
    }


    // 192.168.1.50

    @Test
    public void testCNIPMismatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_ip.pem")));

        Assert.assertFalse("Not match", new DefaultHostnameVerifier().verify("127.0.0.1", cert));
    }

    @Test
    public void testWCMismatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_cn_mismatch_ip.pem")));

        Assert.assertFalse("Not match", new DefaultHostnameVerifier().verify("aardvark.cisco.com", cert));
    }

    @Test
    public void testSANMatch()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_match.pem")));
        Assert.assertTrue("Match", new DefaultHostnameVerifier().verify("localhost.cisco.com", cert));
    }


    @Test
    public void testSANMatchIP()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_match_ip.pem")));
        Assert.assertTrue("Match", new DefaultHostnameVerifier().verify("192.168.51.140", cert));
        Assert.assertTrue("Match", new DefaultHostnameVerifier().verify("127.0.0.1", cert));
        Assert.assertFalse("Not Match", new DefaultHostnameVerifier().verify("10.0.0.1", cert));
    }

    @Test
    public void testSANMatchWC()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch.pem")));
        Assert.assertTrue("Match", new DefaultHostnameVerifier().verify("roundhouse.cisco.com", cert));
        Assert.assertFalse("Not Match", new DefaultHostnameVerifier().verify("aardvark.cisco.com", cert));
    }

    @Test
    public void testSANMismatchIP()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_ip.pem")));
        Assert.assertFalse("Not Match", new DefaultHostnameVerifier().verify("localhost.me", cert));
    }


    @Test
    public void testSANMismatchWC()
        throws Exception
    {
        X509Certificate cert = ESTTestUtils.toJavaX509Certificate(ESTTestUtils.readPemCertificate(
            ESTServerUtils.makeRelativeToServerHome("/san/cert_san_mismatch_ip.pem")));
        Assert.assertFalse("Not Match", new DefaultHostnameVerifier().verify("localhost.me", cert));
    }


}
