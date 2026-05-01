package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.engines.RomulusEngine;
import org.bouncycastle.util.Arrays;

/**
 * Romulus v1.3, based on the current round 3 submission, https://romulusae.github.io/romulus/
 * Reference C implementation: https://github.com/romulusae/romulus
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
 */

public class RomulusDigest
    extends BufferBaseDigest
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();

        private Friend()
        {
        }
    }

    private final byte[] h = new byte[16];
    private final byte[] g = new byte[16];
    /*
     * This file includes only the encryption function of SKINNY-128-384+ as required by Romulus-v1.3
     */
// Packing of data is done as follows (state[i][j] stands for row i and column j):
// 0  1  2  3
// 4  5  6  7
// 8  9 10 11
//12 13 14 15

    public RomulusDigest()
    {
        super(ProcessingBufferType.Immediate, 32);
        DigestSize = 32;
        algorithmName = "Romulus Hash";
    }

    @Override
    protected void processBytes(byte[] input, int inOff)
    {
        RomulusEngine.hirose_128_128_256(Friend.INSTANCE, h, g, input, inOff);
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        Arrays.fill(m_buf, m_bufPos, 31, (byte)0);
        m_buf[31] = (byte)(m_bufPos & 0x1f);
        h[0] ^= 2;
        RomulusEngine.hirose_128_128_256(Friend.INSTANCE, h, g, m_buf, 0);
        // Assign the output tag
        System.arraycopy(h, 0, output, outOff, 16);
        System.arraycopy(g, 0, output, 16 + outOff, 16);
    }

    @Override
    public void reset()
    {
        super.reset();
        Arrays.clear(h);
        Arrays.clear(g);
    }
}
