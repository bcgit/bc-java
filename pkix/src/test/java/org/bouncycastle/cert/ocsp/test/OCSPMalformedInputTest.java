package org.bouncycastle.cert.ocsp.test;

import java.io.IOException;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.util.test.SimpleTest;

/**
 * A malformed encoding handed to the OCSPResp(byte[]) / OCSPReq(byte[]) parsers must be reported
 * through the declared IOException, not as an unchecked exception. A top-level SEQUENCE that is
 * empty or truncated makes OCSPResponse/OCSPRequest read seq.getObjectAt(0) out of bounds, and the
 * parsers only caught IllegalArgumentException/ClassCastException/ASN1Exception, so the
 * ArrayIndexOutOfBoundsException escaped the throws IOException contract (same shape already
 * handled by X509CertificateHolder / X509CRLHolder).
 */
public class OCSPMalformedInputTest
    extends SimpleTest
{
    public String getName()
    {
        return "OCSPMalformedInputTest";
    }

    public void performTest()
        throws Exception
    {
        // empty SEQUENCE, one-element SEQUENCE holding a truncated inner SEQUENCE, and a
        // non-SEQUENCE top-level element.
        byte[][] malformed = new byte[][]
        {
            new byte[]{ 0x30, 0x00 },
            new byte[]{ 0x30, 0x03, 0x30, 0x01, 0x00 },
            new byte[]{ 0x02, 0x01, 0x00 },
        };

        for (int i = 0; i != malformed.length; i++)
        {
            checkResp(malformed[i]);
            checkReq(malformed[i]);
        }

        // well-formed input still parses without change.
        byte[] validResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, null).getEncoded();
        new OCSPResp(validResp);

        byte[] validReq = new OCSPReqBuilder().build().getEncoded();
        new OCSPReq(validReq);
    }

    private void checkResp(byte[] encoding)
    {
        boolean reported = false;
        try
        {
            new OCSPResp(encoding);
        }
        catch (IOException e)
        {
            reported = true;
        }
        catch (Exception e)
        {
            fail("OCSPResp threw " + e.getClass().getName() + " rather than IOException", e);
        }

        if (!reported)
        {
            fail("malformed OCSP response accepted");
        }
    }

    private void checkReq(byte[] encoding)
    {
        boolean reported = false;
        try
        {
            new OCSPReq(encoding);
        }
        catch (IOException e)
        {
            reported = true;
        }
        catch (Exception e)
        {
            fail("OCSPReq threw " + e.getClass().getName() + " rather than IOException", e);
        }

        if (!reported)
        {
            fail("malformed OCSP request accepted");
        }
    }

    public static void main(String[] args)
    {
        runTest(new OCSPMalformedInputTest());
    }
}
