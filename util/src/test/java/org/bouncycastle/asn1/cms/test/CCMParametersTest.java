package org.bouncycastle.asn1.cms.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CCMParameters;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/*
 * RFC 5084 constrains the AEAD ICV length to a small set of values. Parsing an out-of-range length from an
 * untrusted AlgorithmIdentifier (e.g. a CMS content-encryption algorithm) must be rejected; in particular a
 * zero length must not be accepted, since it can defeat the AEAD tag check on decryption.
 */
public class CCMParametersTest
    extends TestCase
{
    public static Test suite()
    {
        return new TestSuite(CCMParametersTest.class);
    }

    private static ASN1Sequence seq(int icvLen)
    {
        return new DERSequence(DEROctetString.withContents(new byte[12]), ASN1Integer.valueOf(icvLen));
    }

    private static ASN1Sequence seqNoICV()
    {
        return new DERSequence(DEROctetString.withContents(new byte[12]));
    }

    public void testDefaultIcvLen()
    {
        assertEquals(12, CCMParameters.getInstance(seqNoICV()).getIcvLen());
    }

    public void testInvalidIcvLen()
    {
        int[] invalid = new int[]{ -1, 0, 2, 3, 5, 7, 9, 11, 13, 15, 17, 18 };
        for (int i = 0; i < invalid.length; ++i)
        {
            int icvLen = invalid[i];
            try
            {
                CCMParameters.getInstance(seq(icvLen));
                fail("invalid icvLen accepted");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
            try
            {
                new CCMParameters(new byte[12], icvLen);
                fail("invalid icvLen accepted");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }
    }

    public void testValidIcvLen()
    {
        int[] valid = new int[]{ 4, 6, 8, 10, 12, 14, 16 };
        for (int i = 0; i < valid.length; ++i)
        {
            int icvLen = valid[i];
            assertEquals(icvLen, CCMParameters.getInstance(seq(icvLen)).getIcvLen());
            assertEquals(icvLen, new CCMParameters(new byte[12], icvLen).getIcvLen());
        }
    }
}
