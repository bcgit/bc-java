package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;

/**
 * Well-formedness checks on LMS / HSS public key parsing, RFC 8554:
 * unknown typecodes and out-of-range level counts must be rejected with a
 * clean exception (sec. 5.3 / 6), and a byte[] encoding must be consumed
 * exactly (sec. 5.3, "If the public key is not exactly 24 + m bytes long,
 * return INVALID").
 */
public class PublicKeyParseTests
    extends TestCase
{
    // lms_sha256_n32_h5 (5) / sha256_n32_w8 (4), I = 16 bytes, T[1] = 32 bytes.
    private static byte[] validLmsPublicKey()
    {
        return Composer.compose()
            .u32str(LMSigParameters.lms_sha256_n32_h5.getType())
            .u32str(LMOtsParameters.sha256_n32_w8.getType())
            .bytes(new byte[16])
            .bytes(new byte[32])
            .build();
    }

    private static byte[] validHssPublicKey(int l)
    {
        return Composer.compose().u32str(l).bytes(validLmsPublicKey()).build();
    }

    public void testValidKeysParse()
        throws Exception
    {
        LMSPublicKeyParameters lmsKey = LMSPublicKeyParameters.getInstance(validLmsPublicKey());
        assertEquals(LMSigParameters.lms_sha256_n32_h5, lmsKey.getSigParameters());
        assertEquals(LMOtsParameters.sha256_n32_w8, lmsKey.getOtsParameters());

        HSSPublicKeyParameters hssKey = HSSPublicKeyParameters.getInstance(validHssPublicKey(1));
        assertEquals(1, hssKey.getL());
        assertEquals(lmsKey, hssKey.getLMSPublicKey());

        assertEquals(8, HSSPublicKeyParameters.getInstance(validHssPublicKey(8)).getL());
    }

    public void testUnknownLMSTypeCodeRejected()
    {
        byte[] enc = validLmsPublicKey();
        enc[3] = (byte)0xee;

        try
        {
            LMSPublicKeyParameters.getInstance(enc);
            fail("unknown LMS typecode accepted");
        }
        catch (IOException e)
        {
            assertEquals("unknown LMS type code: 238", e.getMessage());
        }
    }

    public void testUnknownOtsTypeCodeRejected()
    {
        byte[] enc = validLmsPublicKey();
        enc[7] = (byte)0xee;

        try
        {
            LMSPublicKeyParameters.getInstance(enc);
            fail("unknown LM-OTS typecode accepted");
        }
        catch (IOException e)
        {
            assertEquals("unknown LM-OTS type code: 238", e.getMessage());
        }
    }

    public void testUnknownTypeCodeRejectedViaHSS()
    {
        byte[] enc = validHssPublicKey(1);
        enc[7] = (byte)0xee;

        try
        {
            HSSPublicKeyParameters.getInstance(enc);
            fail("unknown LMS typecode accepted");
        }
        catch (IOException e)
        {
            assertEquals("unknown LMS type code: 238", e.getMessage());
        }
    }

    public void testHssLevelCountRange()
        throws Exception
    {
        int[] badL = new int[]{ 0, 9, 99, -1 };
        for (int i = 0; i != badL.length; i++)
        {
            try
            {
                HSSPublicKeyParameters.getInstance(validHssPublicKey(badL[i]));
                fail("HSS L value " + badL[i] + " accepted");
            }
            catch (IOException e)
            {
                assertEquals("L value of HSS public key out of range: " + badL[i], e.getMessage());
            }
        }
    }

    public void testTrailingDataRejected()
    {
        byte[] lmsTrailing = Arrays.append(validLmsPublicKey(), (byte)0);

        try
        {
            LMSPublicKeyParameters.getInstance(lmsTrailing);
            fail("trailing data after LMS public key accepted");
        }
        catch (IOException e)
        {
            assertEquals("unexpected data found after LMS public key", e.getMessage());
        }

        byte[] hssTrailing = Arrays.append(validHssPublicKey(2), (byte)0);

        try
        {
            HSSPublicKeyParameters.getInstance(hssTrailing);
            fail("trailing data after HSS public key accepted");
        }
        catch (IOException e)
        {
            assertEquals("unexpected data found after HSS public key", e.getMessage());
        }
    }

    /**
     * The stream entry points are used to read public keys embedded in larger
     * structures (HSS signature chains), so they must not require the stream
     * to be exhausted.
     */
    public void testStreamParseLeavesTrailingData()
        throws Exception
    {
        byte[] two = Arrays.concatenate(validLmsPublicKey(), validLmsPublicKey());
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(two));

        LMSPublicKeyParameters first = LMSPublicKeyParameters.getInstance(in);
        LMSPublicKeyParameters second = LMSPublicKeyParameters.getInstance(in);
        assertEquals(first, second);
        assertEquals(0, in.available());
    }
}
