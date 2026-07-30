package org.bouncycastle.openpgp.test;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * PGPPad.unpadSessionData receives the RFC 3394 AES-KW plaintext of an ECDH-encrypted session key.
 * The sender knows the recipient's public subkey, so it derives the RFC 6637 KEK legitimately and
 * can wrap any payload it likes - the unwrap then succeeds and hands whatever it chose to this
 * method. It read the pad count without checking it against the buffer length, and a count past the
 * end makes the constant-time mask -1 at every index, so a uniform buffer satisfies the pad
 * consistency check and reaches new byte[negative]: an unchecked NegativeArraySizeException in place
 * of the declared PGPException, on the ordinary receive path of any client with an ECDH subkey. A
 * zero-length buffer read encoded[-1] for the same reason.
 */
public class PGPPadTest
    extends SimpleTest
{
    public String getName()
    {
        return "PGPPadTest";
    }

    public void performTest()
        throws Exception
    {
        padCountPastEndIsRejected();
        shortBufferIsRejected();
        roundTripsUnchanged();
        badPaddingStillRejected();
    }

    /**
     * Any uniform buffer of a permitted length works, not just the 40 bytes of 0xFF in the report:
     * the length has to be a multiple of eight and no more than 40 to reach the allocation.
     */
    private void padCountPastEndIsRejected()
    {
        int[] lengths = new int[]{8, 16, 24, 32, 40};

        for (int i = 0; i != lengths.length; i++)
        {
            byte[] hostile = new byte[lengths[i]];
            Arrays.fill(hostile, (byte)0xFF);

            assertRejected("uniform 0xFF of length " + lengths[i], hostile);
        }

        // and a pad count only just past the end, rather than the maximum
        byte[] justOver = new byte[8];
        Arrays.fill(justOver, (byte)9);
        assertRejected("pad count 9 in 8 bytes", justOver);
    }

    private void shortBufferIsRejected()
    {
        assertRejected("empty", new byte[0]);
        assertRejected("one byte", new byte[]{(byte)1});
        assertRejected("seven bytes", new byte[7]);
    }

    private void assertRejected(String label, byte[] encoded)
    {
        try
        {
            PGPPad.unpadSessionData(encoded);
            fail(label + ": accepted");
        }
        catch (PGPException e)
        {
            isTrue(label + ": " + e.getMessage(),
                "bad padding found in session data".equals(e.getMessage()));
        }
        catch (RuntimeException e)
        {
            fail(label + ": unchecked " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    /**
     * The compatibility assertion: everything padSessionData produces still unpads. Note the two
     * halves are not total inverses and were not before this change - unpadSessionData requires a
     * padded length of at most 40, while padSessionData pads a 40-byte or longer input out to 48 or
     * more, which unpad then rejects. Real session info is an algorithm byte, a key and a two-byte
     * checksum, so it stays well inside 40; the loop stops there rather than asserting a round trip
     * that never held.
     */
    private void roundTripsUnchanged()
        throws Exception
    {
        for (int len = 0; len != 40; len++)
        {
            byte[] sessionInfo = new byte[len];
            for (int i = 0; i != len; i++)
            {
                sessionInfo[i] = (byte)(i + 1);
            }

            byte[] padded = PGPPad.padSessionData(sessionInfo);

            isTrue("round trip " + len,
                Arrays.areEqual(sessionInfo, PGPPad.unpadSessionData(padded)));

            byte[] unobfuscated = PGPPad.padSessionData(sessionInfo, false);
            if (unobfuscated.length >= 8 && unobfuscated.length <= 40)
            {
                isTrue("round trip unobfuscated " + len,
                    Arrays.areEqual(sessionInfo, PGPPad.unpadSessionData(unobfuscated)));
            }
        }
    }

    /** And the existing rejection of genuinely inconsistent padding is unaffected. */
    private void badPaddingStillRejected()
    {
        byte[] padded = PGPPad.padSessionData(new byte[]{1, 2, 3});

        // corrupt one pad byte
        byte[] corrupt = Arrays.clone(padded);
        corrupt[padded.length - 2] ^= 0x01;
        assertRejected("corrupted pad byte", corrupt);

        // a length that is not a multiple of eight
        assertRejected("length 41", new byte[41]);

        // longer than the 40 bytes padSessionData tops out at
        byte[] tooLong = new byte[48];
        Arrays.fill(tooLong, (byte)8);
        assertRejected("length 48", tooLong);
    }

    public static void main(String[] args)
    {
        runTest(new PGPPadTest());
    }
}
