package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.OutputLengthException;
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
    implements ExtendedDigest
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();
        private Friend() {}
    }

    public enum SparkleParameters
    {
        ESCH256,
        ESCH384
    }

    private static final int RATE_BYTES = 16;
    private static final int RATE_WORDS = 4;

    private String algorithmName;
    private final int[] state;
    private final byte[] m_buf = new byte[RATE_BYTES];
    private final int DIGEST_BYTES;
    private final int SPARKLE_STEPS_SLIM;
    private final int SPARKLE_STEPS_BIG;
    private final int STATE_WORDS;

    private int m_bufPos = 0;

    public SparkleDigest(SparkleParameters sparkleParameters)
    {
        switch (sparkleParameters)
        {
        case ESCH256:
            algorithmName = "ESCH-256";
            DIGEST_BYTES = 32;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            STATE_WORDS = 12;
            break;
        case ESCH384:
            algorithmName = "ESCH-384";
            DIGEST_BYTES = 48;
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
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    @Override
    public int getDigestSize()
    {
        return DIGEST_BYTES;
    }

    @Override
    public int getByteLength()
    {
        return RATE_BYTES;
    }

    @Override
    public void update(byte input)
    {
        if (m_bufPos == RATE_BYTES)
        {
            processBlock(m_buf, 0, SPARKLE_STEPS_SLIM);
            m_bufPos = 0;
        }

        m_buf[m_bufPos++] = input;
    }

    @Override
    public void update(byte[] in, int inOff, int len)
    {
        if (inOff > in.length - len)
        {
            throw new DataLengthException(algorithmName + " input buffer too short");
        }

        if (len < 1)
            return;

        int available = RATE_BYTES - m_bufPos;
        if (len <= available)
        {
            System.arraycopy(in, inOff, m_buf, m_bufPos, len);
            m_bufPos += len;
            return;
        }

        int inPos = 0;
        if (m_bufPos > 0)
        {
            System.arraycopy(in, inOff, m_buf, m_bufPos, available);
            processBlock(m_buf, 0, SPARKLE_STEPS_SLIM);
            inPos += available;
        }

        int remaining;
        while ((remaining = len - inPos) > RATE_BYTES)
        {
            processBlock(in, inOff + inPos, SPARKLE_STEPS_SLIM);
            inPos += RATE_BYTES;
        }

        System.arraycopy(in, inOff + inPos, m_buf, 0, remaining);
        m_bufPos = remaining;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        if (outOff > output.length - DIGEST_BYTES)
        {
            throw new OutputLengthException(algorithmName + " input buffer too short");
        }

        // addition of constant M1 or M2 to the state
        if (m_bufPos < RATE_BYTES)
        {
            state[(STATE_WORDS >> 1) - 1] ^= 1 << 24;

            // padding
            m_buf[m_bufPos] = (byte)0x80;
            while(++m_bufPos < RATE_BYTES)
            {
                m_buf[m_bufPos] = 0x00;
            }
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

        reset();
        return DIGEST_BYTES;
    }

    @Override
    public void reset()
    {
        Arrays.fill(state, 0);
        Arrays.fill(m_buf, (byte)0);
        m_bufPos = 0;
    }

    private void processBlock(byte[] buf, int off, int steps)
    {
        int t0 = Pack.littleEndianToInt(buf, off     );
        int t1 = Pack.littleEndianToInt(buf, off +  4);
        int t2 = Pack.littleEndianToInt(buf, off +  8);
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
