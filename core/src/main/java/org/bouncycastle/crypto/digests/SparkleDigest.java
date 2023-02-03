package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Sparkle v1.2, based on the current round 3 submission, https://sparkle-lwc.github.io/
 * Reference C implementation: https://github.com/cryptolu/sparkle
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
 */
public class SparkleDigest
    implements Digest
{
    public enum SparkleParameters
    {
        ESCH256,
        ESCH384
    }

    private String algorithmName;
    private final int[] state;
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private final int DIGEST_BYTES;
    private final int SPARKLE_STEPS_SLIM;
    private final int SPARKLE_STEPS_BIG;
    private final int STATE_BRANS;
    private final int STATE_WORDS;
    private final int RATE_WORDS;
    private final int RATE_BYTES;

    public SparkleDigest(SparkleParameters sparkleParameters)
    {
        int ESCH_DIGEST_LEN;
        int SPARKLE_STATE;
        int SPARKLE_RATE = 128;
        switch (sparkleParameters)
        {
        case ESCH256:
            ESCH_DIGEST_LEN = 256;
            SPARKLE_STATE = 384;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            algorithmName = "ESCH-256";
            break;
        case ESCH384:
            ESCH_DIGEST_LEN = 384;
            SPARKLE_STATE = 512;
            SPARKLE_STEPS_SLIM = 8;
            SPARKLE_STEPS_BIG = 12;
            algorithmName = "ESCH-384";
            break;
        default:
            throw new IllegalArgumentException("Invalid definition of SCHWAEMM instance");
        }
        STATE_BRANS = SPARKLE_STATE >>> 6;
        STATE_WORDS = SPARKLE_STATE >>> 5;
        RATE_WORDS = SPARKLE_RATE >>> 5;
        RATE_BYTES = SPARKLE_RATE >>> 3;
        DIGEST_BYTES = ESCH_DIGEST_LEN >>> 3;
        state = new int[STATE_WORDS];
    }

    private int ROT(int x, int n)
    {
        return (((x) >>> n) | ((x) << (32 - n)));
    }

    private int ELL(int x)
    {
        return ROT(((x) ^ ((x) << 16)), 16);
    }

    private static final int[] RCON = {0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57,
        0xCFBFA1C8, 0xC2B3293D};

    private void sparkle_opt(int[] state, int brans, int steps)
    {
        int i, j, rc, tmpx, tmpy, x0, y0;
        for (i = 0; i < steps; i++)
        {
            // Add round ant
            state[1] ^= RCON[i & 7];
            state[3] ^= i;
            // ARXBOX layer
            for (j = 0; j < 2 * brans; j += 2)
            {
                rc = RCON[j >>> 1];
                state[j] += ROT(state[j + 1], 31);
                state[j + 1] ^= ROT(state[j], 24);
                state[j] ^= rc;
                state[j] += ROT(state[j + 1], 17);
                state[j + 1] ^= ROT(state[j], 17);
                state[j] ^= rc;
                state[j] += state[j + 1];
                state[j + 1] ^= ROT(state[j], 31);
                state[j] ^= rc;
                state[j] += ROT(state[j + 1], 24);
                state[j + 1] ^= ROT(state[j], 16);
                state[j] ^= rc;
            }
            // Linear layer
            tmpx = x0 = state[0];
            tmpy = y0 = state[1];
            for (j = 2; j < brans; j += 2)
            {
                tmpx ^= state[j];
                tmpy ^= state[j + 1];
            }
            tmpx = ELL(tmpx);
            tmpy = ELL(tmpy);
            for (j = 2; j < brans; j += 2)
            {
                state[j - 2] = state[j + brans] ^ state[j] ^ tmpy;
                state[j + brans] = state[j];
                state[j - 1] = state[j + brans + 1] ^ state[j + 1] ^ tmpx;
                state[j + brans + 1] = state[j + 1];
            }
            state[brans - 2] = state[brans] ^ x0 ^ tmpy;
            state[brans] = x0;
            state[brans - 1] = state[brans + 1] ^ y0 ^ tmpx;
            state[brans + 1] = y0;
        }
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
    public void update(byte input)
    {
        message.write(input);
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException(algorithmName + " input buffer too short");
        }
        message.write(input, inOff, len);
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        if (outOff + DIGEST_BYTES > output.length)
        {
            throw new OutputLengthException(algorithmName + " input buffer too short");
        }
        byte[] input = message.toByteArray();
        int inlen = input.length, i, tmpx, tmpy, inOff = 0;
        // Main Hashing Loop
        int[] in32 = Pack.littleEndianToInt(input, 0, inlen >> 2);
        while (inlen > RATE_BYTES)
        {
            // addition of a message block to the state
            tmpx = 0;
            tmpy = 0;
            for (i = 0; i < RATE_WORDS; i += 2)
            {
                tmpx ^= in32[i + (inOff >> 2)];
                tmpy ^= in32[i + 1 + (inOff >> 2)];
            }
            tmpx = ELL(tmpx);
            tmpy = ELL(tmpy);
            for (i = 0; i < RATE_WORDS; i += 2)
            {
                state[i] ^= (in32[i + (inOff >> 2)] ^ tmpy);
                state[i + 1] ^= (in32[i + 1 + (inOff >> 2)] ^ tmpx);
            }
            for (i = RATE_WORDS; i < (STATE_WORDS / 2); i += 2)
            {
                state[i] ^= tmpy;
                state[i + 1] ^= tmpx;
            }
            // execute SPARKLE with slim number of steps
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
            inlen -= RATE_BYTES;
            inOff += RATE_BYTES;
        }
        // Hashing of Last Block
        // addition of constant M1 or M2 to the state
        state[STATE_BRANS - 1] ^= ((inlen < RATE_BYTES) ? (1 << 24) : (1 << 25));
        // addition of last msg block (incl. padding)
        int[] buffer = new int[RATE_WORDS];
        for (i = 0; i < inlen; ++i)
        {
            buffer[i >>> 2] |= (input[inOff++] & 0xff) << ((i & 3) << 3);
        }
        if (inlen < RATE_BYTES)
        {  // padding
            buffer[i >>> 2] |= 0x80 << ((i & 3) << 3);
        }
        tmpx = 0;
        tmpy = 0;
        for (i = 0; i < RATE_WORDS; i += 2)
        {
            tmpx ^= buffer[i];
            tmpy ^= buffer[i + 1];
        }
        tmpx = ELL(tmpx);
        tmpy = ELL(tmpy);
        for (i = 0; i < RATE_WORDS; i += 2)
        {
            state[i] ^= (buffer[i] ^ tmpy);
            state[i + 1] ^= (buffer[i + 1] ^ tmpx);
        }
        for (i = RATE_WORDS; i < (STATE_WORDS / 2); i += 2)
        {
            state[i] ^= tmpy;
            state[i + 1] ^= tmpx;
        }
        // execute SPARKLE with big number of steps
        sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
        Pack.intToLittleEndian(state, 0, RATE_WORDS, output, outOff);
        int outlen = RATE_BYTES;
        outOff += RATE_BYTES;
        while (outlen < DIGEST_BYTES)
        {
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
            Pack.intToLittleEndian(state, 0, RATE_WORDS, output, outOff);
            outlen += RATE_BYTES;
            outOff += RATE_BYTES;
        }
        return DIGEST_BYTES;
    }

    @Override
    public void reset()
    {
        Arrays.fill(state, (byte)0);
        message.reset();
    }
}
