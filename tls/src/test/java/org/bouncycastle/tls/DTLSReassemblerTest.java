package org.bouncycastle.tls;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;

/**
 * DTLSReassembler tracks the not-yet-received ranges of a handshake message in a list that
 * contributeFragment rescans from the start, and every interior fragment splits a range in two.
 * Single-byte fragments at alternating offsets therefore drove the range count to half the message
 * length and made reassembly quadratic in that length - seconds of CPU per message_seq in the
 * flight, on a DTLS peer that has not yet been verified, and a DTLS client needs no cookie so
 * DTLSVerifier does not cover it. The range count is now capped; at the cap an interior fragment is
 * still copied but leaves its range whole, so completion can be delayed but never happens without
 * every byte having arrived.
 */
public class DTLSReassemblerTest
    extends TestCase
{
    private static final short MSG_TYPE = HandshakeType.certificate;

    public void testAlternatingSingleByteFragmentsStayCheap()
    {
        int length = 128 * 1024;

        DTLSReassembler r = new DTLSReassembler(MSG_TYPE, length);

        long start = System.currentTimeMillis();

        // the hostile shape: one byte at every second offset, each splitting a tracked range
        for (int off = 0; off + 1 < length; off += 2)
        {
            r.contributeFragment(MSG_TYPE, length, new byte[]{(byte)0xFF}, 0, off, 1);
        }

        long elapsed = System.currentTimeMillis() - start;

        // uncapped this is ~70s at this length; capped it is milliseconds
        assertTrue("reassembly took " + elapsed + "ms", elapsed < 10000L);

        // half the bytes are still missing, so the message must not be complete
        assertNull(r.getBodyIfComplete());
    }

    public void testCapDoesNotPreventCompletion()
    {
        int length = 8192;

        byte[] full = new byte[length];
        for (int i = 0; i != length; ++i)
        {
            full[i] = (byte)i;
        }

        DTLSReassembler r = new DTLSReassembler(MSG_TYPE, length);

        for (int off = 0; off + 1 < length; off += 2)
        {
            r.contributeFragment(MSG_TYPE, length, new byte[]{full[off]}, 0, off, 1);
        }
        assertNull(r.getBodyIfComplete());

        // retransmitting the whole flight still completes the message, gaps and cap notwithstanding
        r.contributeFragment(MSG_TYPE, length, full, 0, 0, length);

        assertTrue(Arrays.areEqual(full, r.getBodyIfComplete()));
    }

    public void testFirstFragmentToCoverAByteWins()
    {
        int length = 4;

        DTLSReassembler r = new DTLSReassembler(MSG_TYPE, length);

        r.contributeFragment(MSG_TYPE, length, new byte[]{1, 2}, 0, 0, 2);

        // a later fragment must not rewrite bytes already held
        r.contributeFragment(MSG_TYPE, length, new byte[]{9, 9, 3, 4}, 0, 0, 4);

        assertTrue(Arrays.areEqual(new byte[]{1, 2, 3, 4}, r.getBodyIfComplete()));
    }

    public void testInOrderAndReverseOrderReassembly()
    {
        int length = 4096;
        int fragmentLength = 512;

        byte[] expected = new byte[length];
        for (int i = 0; i != length; ++i)
        {
            expected[i] = (byte)(i * 7);
        }

        DTLSReassembler forwards = new DTLSReassembler(MSG_TYPE, length);
        for (int off = 0; off != length; off += fragmentLength)
        {
            assertNull(forwards.getBodyIfComplete());
            forwards.contributeFragment(MSG_TYPE, length, expected, off, off, fragmentLength);
        }
        assertTrue(Arrays.areEqual(expected, forwards.getBodyIfComplete()));

        DTLSReassembler backwards = new DTLSReassembler(MSG_TYPE, length);
        for (int off = length - fragmentLength; off >= 0; off -= fragmentLength)
        {
            assertNull(backwards.getBodyIfComplete());
            backwards.contributeFragment(MSG_TYPE, length, expected, off, off, fragmentLength);
        }
        assertTrue(Arrays.areEqual(expected, backwards.getBodyIfComplete()));
    }

    public void testOverlappingAndDuplicateFragments()
    {
        int length = 100;

        byte[] expected = new byte[length];
        for (int i = 0; i != length; ++i)
        {
            expected[i] = (byte)(0x40 + i);
        }

        DTLSReassembler r = new DTLSReassembler(MSG_TYPE, length);

        r.contributeFragment(MSG_TYPE, length, expected, 20, 20, 30);
        r.contributeFragment(MSG_TYPE, length, expected, 20, 20, 30);
        r.contributeFragment(MSG_TYPE, length, expected, 40, 40, 40);
        assertNull(r.getBodyIfComplete());

        r.contributeFragment(MSG_TYPE, length, expected, 0, 0, 25);
        assertNull(r.getBodyIfComplete());

        r.contributeFragment(MSG_TYPE, length, expected, 75, 75, 25);
        assertTrue(Arrays.areEqual(expected, r.getBodyIfComplete()));
    }

    public void testEmptyMessageAndReset()
    {
        DTLSReassembler empty = new DTLSReassembler(MSG_TYPE, 0);
        assertNull(empty.getBodyIfComplete());
        empty.contributeFragment(MSG_TYPE, 0, new byte[0], 0, 0, 0);
        assertNotNull(empty.getBodyIfComplete());

        byte[] data = new byte[]{1, 2, 3, 4};
        DTLSReassembler r = new DTLSReassembler(MSG_TYPE, 4);
        r.contributeFragment(MSG_TYPE, 4, data, 0, 0, 4);
        assertNotNull(r.getBodyIfComplete());

        r.reset();
        assertNull(r.getBodyIfComplete());
    }
}
