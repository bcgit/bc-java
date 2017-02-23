package org.bouncycastle.test.est;


import java.security.cert.TrustAnchor;
import java.util.Collections;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cmc.SimplePKIResponse;
import org.bouncycastle.est.CACertsResponse;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.jcajce.JcaESTServiceBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
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

    @Test(expected = IllegalStateException.class)
    public void testEmptyTrustAnchors()
        throws Exception
    {
        ESTServiceBuilder b = new JcaESTServiceBuilder("", Collections.<TrustAnchor>emptySet());
    }

    @Test(expected = IllegalStateException.class)
    public void testNullTrustAnchors()
        throws Exception
    {
        ESTServiceBuilder b = new JcaESTServiceBuilder("", null);
    }

    @Test
    public void testEnforceTrusting()
        throws Exception
    {
        ESTServiceBuilder b = new JcaESTServiceBuilder("");
        try
        {
            b.build().getCSRAttributes();
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }

        try
        {
            b.build().simpleEnroll(null);
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("Must be illegal state exception", IllegalStateException.class, ex.getClass());
        }


        try
        {
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
        CACertsResponse ca = new CACertsResponse(null, null, null, false);

        TestCase.assertFalse("Must be false, store is null", ca.hasStore());

        ca.getStore();
    }


    @Test()
    public void testCACertsResponseWithStore()
        throws Exception
    {

        String holder =
            "MIIBggYJKoZIhvcNAQcCoIIBczCCAW8CAQExADALBgkqhkiG9w0BBwGgggFXMIIB\n" +
                "UzCB+qADAgECAgkA+syTlV9djhkwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXN0\n" +
                "RXhhbXBsZUNBMB4XDTE3MDIxODAyNTQ1OVoXDTE4MDIxODAyNTQ1OVowFzEVMBMG\n" +
                "A1UEAwwMZXN0RXhhbXBsZUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEobjd\n" +
                "xMcCE5GfVRE4f86ik6yK0erBhAbN8er0u6vWTXlyk5IXJy7HsUmC7Wv1SDRno/Rp\n" +
                "pyVekSu4T0/h7uBeaKMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQU8rjiAzjo\n" +
                "Nldka5gT1bcbQqcESPMwCgYIKoZIzj0EAwIDSAAwRQIhAOwsMtixDryuVUYNBdaf\n" +
                "3tQV1SlvBmCP6y3cKMST45sRAiBEUNYOsYnuFmH93I+0NSJPYuuBY+Zfqrc2awCs\n" +
                "spOU3zEA";

        ASN1InputStream ain = new ASN1InputStream(Base64.decode(holder));
        SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));

        CACertsResponse ca = new CACertsResponse(spkr.getCertificates(), null, null, false);

        TestCase.assertTrue("Must be be, store is defined", ca.hasStore());

        // Throws no exception.
        ca.getStore();

    }


}
