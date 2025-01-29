package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.engines.SparkleEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Sparkle v1.2, based on the current round 3 submission, https://sparkle-lwc.github.io/
 * Reference C implementation: https://github.com/cryptolu/sparkle
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
 */
public class SparkleDigest
    extends BufferBaseDigest
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();

        private Friend()
        {
        }
    }

    public enum SparkleParameters
    {
        ESCH256,
        ESCH384
    }

    private static final int RATE_WORDS = 4;
    private final int[] state;
    private final int SPARKLE_STEPS_SLIM;
    private final int SPARKLE_STEPS_BIG;
    private final int STATE_WORDS;

    public SparkleDigest(SparkleParameters sparkleParameters)
    {
        super(ProcessingBufferType.Buffered, 16);
        switch (sparkleParameters)
        {
        case ESCH256:
            algorithmName = "ESCH-256";
            DigestSize = 32;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            STATE_WORDS = 12;
            break;
        case ESCH384:
            algorithmName = "ESCH-384";
            DigestSize = 48;
            SPARKLE_STEPS_SLIM = 8;
            SPARKLE_STEPS_BIG = 12;
            STATE_WORDS = 16;
            break;
        default:
            throw new IllegalArgumentException("Invalid definition of SCHWAEMM instance");
        }
        state = new int[STATE_WORDS];
    }

    @Override
    protected void processBytes(byte[] input, int inOff)
    {
        processBlock(input, inOff, SPARKLE_STEPS_SLIM);
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        // addition of constant M1 or M2 to the state
        if (m_bufPos < BlockSize)
        {
            state[(STATE_WORDS >> 1) - 1] ^= 1 << 24;

            // padding
            m_buf[m_bufPos++] = (byte)0x80;
            Arrays.fill(m_buf, m_bufPos, BlockSize, (byte)0);
        }
        else
        {
            state[(STATE_WORDS >> 1) - 1] ^= 1 << 25;
        }

        processBlock(m_buf, 0, SPARKLE_STEPS_BIG);

        Pack.intToLittleEndian(state, 0, RATE_WORDS, output, outOff);

        if (STATE_WORDS == 16)
        {
            SparkleEngine.sparkle_opt16(Friend.INSTANCE, state, SPARKLE_STEPS_SLIM);
            Pack.intToLittleEndian(state, 0, RATE_WORDS, output, outOff + 16);
            SparkleEngine.sparkle_opt16(Friend.INSTANCE, state, SPARKLE_STEPS_SLIM);
            Pack.intToLittleEndian(state, 0, RATE_WORDS, output, outOff + 32);
        }
        else
        {
            SparkleEngine.sparkle_opt12(Friend.INSTANCE, state, SPARKLE_STEPS_SLIM);
            Pack.intToLittleEndian(state, 0, RATE_WORDS, output, outOff + 16);
        }
    }

    @Override
    public void reset()
    {
        super.reset();
        Arrays.fill(state, 0);
    }

    private void processBlock(byte[] buf, int off, int steps)
    {
        int t0 = Pack.littleEndianToInt(buf, off);
        int t1 = Pack.littleEndianToInt(buf, off + 4);
        int t2 = Pack.littleEndianToInt(buf, off + 8);
        int t3 = Pack.littleEndianToInt(buf, off + 12);

        // addition of a buffer block to the state
        int tx = ELL(t0 ^ t2);
        int ty = ELL(t1 ^ t3);
        state[0] ^= t0 ^ ty;
        state[1] ^= t1 ^ tx;
        state[2] ^= t2 ^ ty;
        state[3] ^= t3 ^ tx;
        state[4] ^= ty;
        state[5] ^= tx;
        if (STATE_WORDS == 16)
        {
            state[6] ^= ty;
            state[7] ^= tx;
            SparkleEngine.sparkle_opt16(Friend.INSTANCE, state, steps);
        }
        else
        {
            SparkleEngine.sparkle_opt12(Friend.INSTANCE, state, steps);
        }
    }

    private static int ELL(int x)
    {
        return Integers.rotateRight(x, 16) ^ (x & 0xFFFF);
    }
}