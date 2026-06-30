package org.bouncycastle.asn1.cms.test;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.util.Properties;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/*
 * RFC 5084 constrains the AEAD ICV length to a small set of values. Parsing an out-of-range length from an
 * untrusted AlgorithmIdentifier (e.g. a CMS content-encryption algorithm) must be rejected; in particular a
 * zero length must not be accepted, since it can defeat the AEAD tag check on decryption.
 */
public class GCMParametersTest
    extends TestCase
{
    public static Test suite()
    {
        return new TestSuite(GCMParametersTest.class);
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
        assertEquals(12, GCMParameters.getInstance(seqNoICV()).getIcvLen());
    }

    public void testInvalidIcvLen()
    {
        int[] invalid = new int[]{ -1, 0, 11, 17 };
        for (int i = 0; i < invalid.length; ++i)
        {
            int icvLen = invalid[i];
            try
            {
                GCMParameters.getInstance(seq(icvLen));
                fail("invalid icvLen accepted");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
            try
            {
                new GCMParameters(new byte[12], icvLen);
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
        int[] valid = new int[]{ 12, 13, 14, 15, 16 };
        for (int i = 0; i < valid.length; ++i)
        {
            int icvLen = valid[i];
            assertEquals(icvLen, GCMParameters.getInstance(seq(icvLen)).getIcvLen());
            assertEquals(icvLen, new GCMParameters(new byte[12], icvLen).getIcvLen());
        }
    }

    /*
     * Properties.GCM_ALLOW_SHORT_TAGS relaxes the RFC 5084 lower bound (12 octets) to the NIST
     * SP 800-38D minimum of 4 octets (32 bits). It defaults off, and even when set the 4..16 octet
     * window is still enforced at both ends.
     */
    public void testShortTagsProperty()
    {
        // off by default - the RFC 5084 minimum still applies
        for (int icvLen = 4; icvLen < 12; ++icvLen)
        {
            try
            {
                GCMParameters.getInstance(seq(icvLen));
                fail("short tag accepted with property unset");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }

        System.setProperty(Properties.GCM_ALLOW_SHORT_TAGS, "true");
        try
        {
            for (int icvLen = 4; icvLen <= 16; ++icvLen)
            {
                assertEquals(icvLen, GCMParameters.getInstance(seq(icvLen)).getIcvLen());
                assertEquals(icvLen, new GCMParameters(new byte[12], icvLen).getIcvLen());
            }

            // the 4..16 window is still enforced at both ends
            int[] stillInvalid = new int[]{ -1, 0, 3, 17 };
            for (int i = 0; i < stillInvalid.length; ++i)
            {
                try
                {
                    GCMParameters.getInstance(seq(stillInvalid[i]));
                    fail("out-of-window tag accepted with property set");
                }
                catch (IllegalArgumentException e)
                {
                    // expected
                }
            }
        }
        finally
        {
            System.clearProperty(Properties.GCM_ALLOW_SHORT_TAGS);
        }

        // cleared again - the RFC 5084 minimum is back
        try
        {
            GCMParameters.getInstance(seq(4));
            fail("short tag accepted after property cleared");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
}
