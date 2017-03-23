package org.bouncycastle.test.est;


import javax.net.ssl.X509TrustManager;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.CACertsResponse;
import org.bouncycastle.est.CSRAttributesResponse;
import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaJceUtils;
import org.bouncycastle.est.jcajce.JsseESTServiceBuilder;
import org.bouncycastle.est.jcajce.SSLSocketFactoryCreator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Assert;
import org.junit.Test;


/**
 * Test illegal state exceptions are thrown when expected.
 */
public class TestESTServiceFails
    extends SimpleTest
{
    public String getName()
    {
        return "ESTServiceFails";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestESTServiceFails.class);
    }


    @Test(expected = NullPointerException.class)
    public void testSocketFactoryCreator()
        throws Exception
    {
        SSLSocketFactoryCreator socketFactoryCreator = null;
        ESTServiceBuilder b = new JsseESTServiceBuilder("", socketFactoryCreator);
    }

    @Test(expected = NullPointerException.class)
    public void testSocketFactoryCreator_1()
        throws Exception
    {
        X509TrustManager socketFactoryCreator = null;
        ESTServiceBuilder b = new JsseESTServiceBuilder("", socketFactoryCreator);
    }

    @Test(expected = NullPointerException.class)
    public void testSocketFactoryCreator_2()
        throws Exception
    {
        X509TrustManager[] socketFactoryCreator = null;
        ESTServiceBuilder b = new JsseESTServiceBuilder("", socketFactoryCreator);
    }


    @Test
    public void testEnforceTrusting()
        throws Exception
    {
        try
        {
            ESTServiceBuilder b = new JsseESTServiceBuilder("", JcaJceUtils.getTrustAllTrustManager());
            b.build().getCSRAttributes();
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }

        try
        {
            ESTServiceBuilder b = new JsseESTServiceBuilder("", JcaJceUtils.getTrustAllTrustManager());
            b.build().simpleEnroll(null);
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }


        try
        {
            ESTServiceBuilder b = new JsseESTServiceBuilder("", JcaJceUtils.getTrustAllTrustManager());
            b.build().simpleEnroll(false, null, null);
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }

    }

    @Test(expected = IllegalStateException.class)
    public void testCACertsResponseNoStore()
        throws Exception
    {
        CACertsResponse ca = new CACertsResponse(null, null, null, null, false);

        TestCase.assertFalse("Must be false, store is null", ca.hasCertificates());

        ca.getCertificateStore();
    }

    @Test()
    public void testCACertsResponseWithStore()
        throws Exception
    {

        String holder =
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
                "AA==";

        ASN1InputStream ain = new ASN1InputStream(Base64.decode(holder));
        SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));

        CACertsResponse ca = new CACertsResponse(spkr.getCertificates(), spkr.getCRLs(), null, null, false);

        TestCase.assertTrue("Store is defined", ca.hasCertificates());
        TestCase.assertTrue("CRL Store is defined", ca.hasCRLs());


        // Throws no exception.
        ca.getCertificateStore();

    }


    @Test(expected = IllegalStateException.class)
    public void testCACertsResponseNoCRLs()
        throws Exception
    {
        CACertsResponse ca = new CACertsResponse(null, null, null, null, false);

        TestCase.assertFalse("Must be false, store is null", ca.hasCRLs());

        ca.getCrlStore();
    }

    @Test(expected = IllegalStateException.class)
    public void testCSRRequestResponseNoCSRs()
    {
        CSRRequestResponse rsp = new CSRRequestResponse(null, null);
        TestCase.assertFalse("Must be false", rsp.hasAttributesResponse());
        rsp.getAttributesResponse();
        Assert.fail("Must throw exception");
    }

    @Test
    public void testCSRAttributeResponsewithCSRs()
        throws Exception
    {
        CSRRequestResponse rsp = new CSRRequestResponse(
            new CSRAttributesResponse(
                Base64.decode("MFYGBysGAQEBARYGCSqGSIb3DQEJBwYJKyQDAwIIAQELBglghkgBZQMEAgIGCSqGSIb3DQEBAQYJKoZIhvcNAQEEBgkqhkiG9w0BAQUGCSqGSIb3DQEBBg==")),
            null
        );

        TestCase.assertTrue("Response exists", rsp.hasAttributesResponse());

        rsp.getAttributesResponse();

    }


}
