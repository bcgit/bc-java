package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.digests.SparkleDigest;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Sparkle v1.2, based on the current round 3 submission, https://sparkle-lwc.github.io/
 * Reference C implementation: https://github.com/cryptolu/sparkle
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
 */
public class SparkleEngine
    extends AEADBufferBaseEngine
{
    public enum SparkleParameters
    {
        SCHWAEMM128_128,
        SCHWAEMM256_128,
        SCHWAEMM192_192,
        SCHWAEMM256_256
    }

    private static final int[] RCON = {0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57,
        0xCFBFA1C8, 0xC2B3293D};

    private final int[] state;
    private final int[] k;
    private final int[] npub;
    private boolean encrypted;
    private final int m_bufferSizeDecrypt;

    private final int SPARKLE_STEPS_SLIM;
    private final int SPARKLE_STEPS_BIG;
    private final int KEY_WORDS;
    private final int TAG_WORDS;
    private final int STATE_WORDS;
    private final int RATE_WORDS;
    private final int CAP_MASK;
    private final int _A0;
    private final int _A1;
    private final int _M2;
    private final int _M3;

    public SparkleEngine(SparkleParameters sparkleParameters)
    {
        int SPARKLE_STATE;
        int SCHWAEMM_TAG_LEN;
        int SPARKLE_CAPACITY;
        int SCHWAEMM_KEY_LEN;
        int SCHWAEMM_NONCE_LEN;
        switch (sparkleParameters)
        {
        case SCHWAEMM128_128:
            SCHWAEMM_KEY_LEN = 128;
            SCHWAEMM_NONCE_LEN = 128;
            SCHWAEMM_TAG_LEN = 128;
            SPARKLE_STATE = 256;
            SPARKLE_CAPACITY = 128;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 10;
            algorithmName = "SCHWAEMM128-128";
            break;
        case SCHWAEMM256_128:
            SCHWAEMM_KEY_LEN = 128;
            SCHWAEMM_NONCE_LEN = 256;
            SCHWAEMM_TAG_LEN = 128;
            SPARKLE_STATE = 384;
            SPARKLE_CAPACITY = 128;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            algorithmName = "SCHWAEMM256-128";
            break;
        case SCHWAEMM192_192:
            SCHWAEMM_KEY_LEN = 192;
            SCHWAEMM_NONCE_LEN = 192;
            SCHWAEMM_TAG_LEN = 192;
            SPARKLE_STATE = 384;
            SPARKLE_CAPACITY = 192;
            SPARKLE_STEPS_SLIM = 7;
            SPARKLE_STEPS_BIG = 11;
            algorithmName = "SCHWAEMM192-192";
            break;
        case SCHWAEMM256_256:
            SCHWAEMM_KEY_LEN = 256;
            SCHWAEMM_NONCE_LEN = 256;
            SCHWAEMM_TAG_LEN = 256;
            SPARKLE_STATE = 512;
            SPARKLE_CAPACITY = 256;
            SPARKLE_STEPS_SLIM = 8;
            SPARKLE_STEPS_BIG = 12;
            algorithmName = "SCHWAEMM256-256";
            break;
        default:
            throw new IllegalArgumentException("Invalid definition of SCHWAEMM instance");
        }
        KEY_WORDS = SCHWAEMM_KEY_LEN >>> 5;
        KEY_SIZE = SCHWAEMM_KEY_LEN >>> 3;
        TAG_WORDS = SCHWAEMM_TAG_LEN >>> 5;
        MAC_SIZE = SCHWAEMM_TAG_LEN >>> 3;
        STATE_WORDS = SPARKLE_STATE >>> 5;
        RATE_WORDS = SCHWAEMM_NONCE_LEN >>> 5;
        IV_SIZE = SCHWAEMM_NONCE_LEN >>> 3;
        int CAP_BRANS = SPARKLE_CAPACITY >>> 6;
        int CAP_WORDS = SPARKLE_CAPACITY >>> 5;
        CAP_MASK = RATE_WORDS > CAP_WORDS ? CAP_WORDS - 1 : -1;
        _A0 = ((((1 << CAP_BRANS))) << 24);
        _A1 = (((1 ^ (1 << CAP_BRANS))) << 24);
        _M2 = (((2 ^ (1 << CAP_BRANS))) << 24);
        _M3 = (((3 ^ (1 << CAP_BRANS))) << 24);
        state = new int[STATE_WORDS];
        k = new int[KEY_WORDS];
        npub = new int[RATE_WORDS];
        AADBufferSize = BlockSize = IV_SIZE;
        m_bufferSizeDecrypt = IV_SIZE + MAC_SIZE;
        m_buf = new byte[m_bufferSizeDecrypt];
        m_aad = new byte[BlockSize];

        // Relied on by processBytes method for decryption
//        assert RATE_BYTES >= TAG_BYTES;
    }

    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        Pack.littleEndianToInt(key, 0, k);
        Pack.littleEndianToInt(iv, 0, npub);
        initialised = true;
        m_state = forEncryption ? State.EncInit : State.DecInit;

        reset();
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        if (encrypted || m_bufPos > 0)
        {
            // Encryption of Last Block
            // addition of ant M2 or M3 to the state
            state[STATE_WORDS - 1] ^= ((m_bufPos < IV_SIZE) ? _M2 : _M3);
            // combined Rho and rate-whitening (incl. padding)
            // Rho and rate-whitening for the encryption of the last plaintext block. Since
            // this last block may require padding, it is always copied to a buffer.
            int[] buffer = new int[RATE_WORDS];
            for (int i = 0; i < m_bufPos; ++i)
            {
                buffer[i >>> 2] |= (m_buf[i] & 0xFF) << ((i & 3) << 3);
            }
            if (m_bufPos < IV_SIZE)
            {
                if (!forEncryption)
                {
                    int tmp = (m_bufPos & 3) << 3;
                    buffer[m_bufPos >>> 2] |= (state[m_bufPos >>> 2] >>> tmp) << tmp;
                    tmp = (m_bufPos >>> 2) + 1;
                    System.arraycopy(state, tmp, buffer, tmp, RATE_WORDS - tmp);
                }
                buffer[m_bufPos >>> 2] ^= 0x80 << ((m_bufPos & 3) << 3);
            }
            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + RATE_WORDS / 2;

                int s_i = state[i];
                int s_j = state[j];
                if (forEncryption)
                {
                    state[i] = s_j ^ buffer[i] ^ state[RATE_WORDS + i];
                    state[j] = s_i ^ s_j ^ buffer[j] ^ state[RATE_WORDS + (j & CAP_MASK)];
                }
                else
                {
                    state[i] = s_i ^ s_j ^ buffer[i] ^ state[RATE_WORDS + i];
                    state[j] = s_i ^ buffer[j] ^ state[RATE_WORDS + (j & CAP_MASK)];
                }
                buffer[i] ^= s_i;
                buffer[j] ^= s_j;
            }
            for (int i = 0; i < m_bufPos; ++i)
            {
                output[outOff++] = (byte)(buffer[i >>> 2] >>> ((i & 3) << 3));
            }
            // execute SPARKLE with big number of steps
            sparkle_opt(state, SPARKLE_STEPS_BIG);
        }
        // add key to the capacity-part of the state
        for (int i = 0; i < KEY_WORDS; i++)
        {
            state[RATE_WORDS + i] ^= k[i];
        }
        mac = new byte[MAC_SIZE];
        Pack.intToLittleEndian(state, RATE_WORDS, TAG_WORDS, mac, 0);

    }

    protected void processBufferAAD(byte[] buffer, int bufOff)
    {
        for (int i = 0; i < RATE_WORDS / 2; ++i)
        {
            int j = i + (RATE_WORDS / 2);

            int s_i = state[i];
            int s_j = state[j];

            int d_i = Pack.littleEndianToInt(buffer, bufOff + (i * 4));
            int d_j = Pack.littleEndianToInt(buffer, bufOff + (j * 4));

            state[i] = s_j ^ d_i ^ state[RATE_WORDS + i];
            state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];
        }

        sparkle_opt(state, SPARKLE_STEPS_SLIM);
    }

    private void processBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
//        assert bufOff <= buffer.length - RATE_BYTES;

        for (int i = 0; i < RATE_WORDS / 2; ++i)
        {
            int j = i + (RATE_WORDS / 2);

            int s_i = state[i];
            int s_j = state[j];

            int d_i = Pack.littleEndianToInt(buffer, bufOff + (i * 4));
            int d_j = Pack.littleEndianToInt(buffer, bufOff + (j * 4));

            state[i] = s_i ^ s_j ^ d_i ^ state[RATE_WORDS + i];
            state[j] = s_i ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];

            Pack.intToLittleEndian(d_i ^ s_i, output, outOff + (i * 4));
            Pack.intToLittleEndian(d_j ^ s_j, output, outOff + (j * 4));
        }

        sparkle_opt(state, SPARKLE_STEPS_SLIM);

        encrypted = true;
    }

    @Override
    protected void processBuffer(byte[] input, int inOff, byte[] output, int outOff)
    {
        if (forEncryption)
        {
            processBufferEncrypt(input, inOff, output, outOff);
        }
        else
        {
            processBufferDecrypt(input, inOff, output, outOff);
        }
    }

    private void processBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
    {
//      assert bufOff <= buffer.length - RATE_BYTES;

        for (int i = 0; i < RATE_WORDS / 2; ++i)
        {
            int j = i + (RATE_WORDS / 2);

            int s_i = state[i];
            int s_j = state[j];

            int d_i = Pack.littleEndianToInt(buffer, bufOff + (i * 4));
            int d_j = Pack.littleEndianToInt(buffer, bufOff + (j * 4));

            state[i] = s_j ^ d_i ^ state[RATE_WORDS + i];
            state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];

            Pack.intToLittleEndian(d_i ^ s_i, output, outOff + (i * 4));
            Pack.intToLittleEndian(d_j ^ s_j, output, outOff + (j * 4));
        }

        sparkle_opt(state, SPARKLE_STEPS_SLIM);

        encrypted = true;
    }

    protected void processFinalAAD()
    {
        // addition of constant A0 or A1 to the state
        if (m_aadPos < BlockSize)
        {
            state[STATE_WORDS - 1] ^= _A0;

            // padding
            m_aad[m_aadPos] = (byte)0x80;
            while (++m_aadPos < BlockSize)
            {
                m_aad[m_aadPos] = 0x00;
            }
        }
        else
        {
            state[STATE_WORDS - 1] ^= _A1;
        }

        for (int i = 0; i < RATE_WORDS / 2; ++i)
        {
            int j = i + (RATE_WORDS / 2);

            int s_i = state[i];
            int s_j = state[j];

            int d_i = Pack.littleEndianToInt(m_aad, i * 4);
            int d_j = Pack.littleEndianToInt(m_aad, j * 4);

            state[i] = s_j ^ d_i ^ state[RATE_WORDS + i];
            state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];
        }

        sparkle_opt(state, SPARKLE_STEPS_BIG);
    }


    protected void reset(boolean clearMac)
    {
        bufferReset();
        encrypted = false;
        // The Initialize function loads nonce and key into the state and executes the
        // SPARKLE permutation with the big number of steps.
        // load nonce into the rate-part of the state
        System.arraycopy(npub, 0, state, 0, RATE_WORDS);
        // load key into the capacity-part of the sate
        System.arraycopy(k, 0, state, RATE_WORDS, KEY_WORDS);

        sparkle_opt(state, SPARKLE_STEPS_BIG);

        super.reset(clearMac);
    }

    private static int ELL(int x)
    {
        return Integers.rotateRight(x, 16) ^ (x & 0xFFFF);
    }

    private static void sparkle_opt(int[] state, int steps)
    {
        switch (state.length)
        {
        case 8:
            sparkle_opt8(state, steps);
            break;
        case 12:
            sparkle_opt12(state, steps);
            break;
        case 16:
            sparkle_opt16(state, steps);
            break;
        default:
            throw new IllegalStateException();
        }
    }

    static void sparkle_opt8(int[] state, int steps)
    {
        int s00 = state[0];
        int s01 = state[1];
        int s02 = state[2];
        int s03 = state[3];
        int s04 = state[4];
        int s05 = state[5];
        int s06 = state[6];
        int s07 = state[7];

        for (int step = 0; step < steps; ++step)
        {
            // Add round ant

            s01 ^= RCON[step & 7];
            s03 ^= step;

            // ARXBOX layer
            {
                int rc = RCON[0];
                s00 += Integers.rotateRight(s01, 31);
                s01 ^= Integers.rotateRight(s00, 24);
                s00 ^= rc;
                s00 += Integers.rotateRight(s01, 17);
                s01 ^= Integers.rotateRight(s00, 17);
                s00 ^= rc;
                s00 += s01;
                s01 ^= Integers.rotateRight(s00, 31);
                s00 ^= rc;
                s00 += Integers.rotateRight(s01, 24);
                s01 ^= Integers.rotateRight(s00, 16);
                s00 ^= rc;
            }
            {
                int rc = RCON[1];
                s02 += Integers.rotateRight(s03, 31);
                s03 ^= Integers.rotateRight(s02, 24);
                s02 ^= rc;
                s02 += Integers.rotateRight(s03, 17);
                s03 ^= Integers.rotateRight(s02, 17);
                s02 ^= rc;
                s02 += s03;
                s03 ^= Integers.rotateRight(s02, 31);
                s02 ^= rc;
                s02 += Integers.rotateRight(s03, 24);
                s03 ^= Integers.rotateRight(s02, 16);
                s02 ^= rc;
            }
            {
                int rc = RCON[2];
                s04 += Integers.rotateRight(s05, 31);
                s05 ^= Integers.rotateRight(s04, 24);
                s04 ^= rc;
                s04 += Integers.rotateRight(s05, 17);
                s05 ^= Integers.rotateRight(s04, 17);
                s04 ^= rc;
                s04 += s05;
                s05 ^= Integers.rotateRight(s04, 31);
                s04 ^= rc;
                s04 += Integers.rotateRight(s05, 24);
                s05 ^= Integers.rotateRight(s04, 16);
                s04 ^= rc;
            }
            {
                int rc = RCON[3];
                s06 += Integers.rotateRight(s07, 31);
                s07 ^= Integers.rotateRight(s06, 24);
                s06 ^= rc;
                s06 += Integers.rotateRight(s07, 17);
                s07 ^= Integers.rotateRight(s06, 17);
                s06 ^= rc;
                s06 += s07;
                s07 ^= Integers.rotateRight(s06, 31);
                s06 ^= rc;
                s06 += Integers.rotateRight(s07, 24);
                s07 ^= Integers.rotateRight(s06, 16);
                s06 ^= rc;
            }

            // Linear layer

            int t02 = ELL(s00 ^ s02);
            int t13 = ELL(s01 ^ s03);

            int u00 = s00 ^ s04;
            int u01 = s01 ^ s05;
            int u02 = s02 ^ s06;
            int u03 = s03 ^ s07;

            s04 = s00;
            s05 = s01;
            s06 = s02;
            s07 = s03;

            s00 = u02 ^ t13;
            s01 = u03 ^ t02;
            s02 = u00 ^ t13;
            s03 = u01 ^ t02;
        }

        state[0] = s00;
        state[1] = s01;
        state[2] = s02;
        state[3] = s03;
        state[4] = s04;
        state[5] = s05;
        state[6] = s06;
        state[7] = s07;
    }

    static void sparkle_opt12(int[] state, int steps)
    {
        int s00 = state[0];
        int s01 = state[1];
        int s02 = state[2];
        int s03 = state[3];
        int s04 = state[4];
        int s05 = state[5];
        int s06 = state[6];
        int s07 = state[7];
        int s08 = state[8];
        int s09 = state[9];
        int s10 = state[10];
        int s11 = state[11];

        for (int step = 0; step < steps; ++step)
        {
            // Add round ant

            s01 ^= RCON[step & 7];
            s03 ^= step;

            // ARXBOX layer
            {
                int rc = RCON[0];
                s00 += Integers.rotateRight(s01, 31);
                s01 ^= Integers.rotateRight(s00, 24);
                s00 ^= rc;
                s00 += Integers.rotateRight(s01, 17);
                s01 ^= Integers.rotateRight(s00, 17);
                s00 ^= rc;
                s00 += s01;
                s01 ^= Integers.rotateRight(s00, 31);
                s00 ^= rc;
                s00 += Integers.rotateRight(s01, 24);
                s01 ^= Integers.rotateRight(s00, 16);
                s00 ^= rc;
            }
            {
                int rc = RCON[1];
                s02 += Integers.rotateRight(s03, 31);
                s03 ^= Integers.rotateRight(s02, 24);
                s02 ^= rc;
                s02 += Integers.rotateRight(s03, 17);
                s03 ^= Integers.rotateRight(s02, 17);
                s02 ^= rc;
                s02 += s03;
                s03 ^= Integers.rotateRight(s02, 31);
                s02 ^= rc;
                s02 += Integers.rotateRight(s03, 24);
                s03 ^= Integers.rotateRight(s02, 16);
                s02 ^= rc;
            }
            {
                int rc = RCON[2];
                s04 += Integers.rotateRight(s05, 31);
                s05 ^= Integers.rotateRight(s04, 24);
                s04 ^= rc;
                s04 += Integers.rotateRight(s05, 17);
                s05 ^= Integers.rotateRight(s04, 17);
                s04 ^= rc;
                s04 += s05;
                s05 ^= Integers.rotateRight(s04, 31);
                s04 ^= rc;
                s04 += Integers.rotateRight(s05, 24);
                s05 ^= Integers.rotateRight(s04, 16);
                s04 ^= rc;
            }
            {
                int rc = RCON[3];
                s06 += Integers.rotateRight(s07, 31);
                s07 ^= Integers.rotateRight(s06, 24);
                s06 ^= rc;
                s06 += Integers.rotateRight(s07, 17);
                s07 ^= Integers.rotateRight(s06, 17);
                s06 ^= rc;
                s06 += s07;
                s07 ^= Integers.rotateRight(s06, 31);
                s06 ^= rc;
                s06 += Integers.rotateRight(s07, 24);
                s07 ^= Integers.rotateRight(s06, 16);
                s06 ^= rc;
            }
            {
                int rc = RCON[4];
                s08 += Integers.rotateRight(s09, 31);
                s09 ^= Integers.rotateRight(s08, 24);
                s08 ^= rc;
                s08 += Integers.rotateRight(s09, 17);
                s09 ^= Integers.rotateRight(s08, 17);
                s08 ^= rc;
                s08 += s09;
                s09 ^= Integers.rotateRight(s08, 31);
                s08 ^= rc;
                s08 += Integers.rotateRight(s09, 24);
                s09 ^= Integers.rotateRight(s08, 16);
                s08 ^= rc;
            }
            {
                int rc = RCON[5];
                s10 += Integers.rotateRight(s11, 31);
                s11 ^= Integers.rotateRight(s10, 24);
                s10 ^= rc;
                s10 += Integers.rotateRight(s11, 17);
                s11 ^= Integers.rotateRight(s10, 17);
                s10 ^= rc;
                s10 += s11;
                s11 ^= Integers.rotateRight(s10, 31);
                s10 ^= rc;
                s10 += Integers.rotateRight(s11, 24);
                s11 ^= Integers.rotateRight(s10, 16);
                s10 ^= rc;
            }

            // Linear layer

            int t024 = ELL(s00 ^ s02 ^ s04);
            int t135 = ELL(s01 ^ s03 ^ s05);

            int u00 = s00 ^ s06;
            int u01 = s01 ^ s07;
            int u02 = s02 ^ s08;
            int u03 = s03 ^ s09;
            int u04 = s04 ^ s10;
            int u05 = s05 ^ s11;

            s06 = s00;
            s07 = s01;
            s08 = s02;
            s09 = s03;
            s10 = s04;
            s11 = s05;

            s00 = u02 ^ t135;
            s01 = u03 ^ t024;
            s02 = u04 ^ t135;
            s03 = u05 ^ t024;
            s04 = u00 ^ t135;
            s05 = u01 ^ t024;
        }

        state[0] = s00;
        state[1] = s01;
        state[2] = s02;
        state[3] = s03;
        state[4] = s04;
        state[5] = s05;
        state[6] = s06;
        state[7] = s07;
        state[8] = s08;
        state[9] = s09;
        state[10] = s10;
        state[11] = s11;
    }

    public static void sparkle_opt12(SparkleDigest.Friend friend, int[] state, int steps)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by SparkleDigest");
        }

        sparkle_opt12(state, steps);
    }

    static void sparkle_opt16(int[] state, int steps)
    {
//        assert (steps & 1) == 0;

        int s00 = state[0];
        int s01 = state[1];
        int s02 = state[2];
        int s03 = state[3];
        int s04 = state[4];
        int s05 = state[5];
        int s06 = state[6];
        int s07 = state[7];
        int s08 = state[8];
        int s09 = state[9];
        int s10 = state[10];
        int s11 = state[11];
        int s12 = state[12];
        int s13 = state[13];
        int s14 = state[14];
        int s15 = state[15];

        for (int step = 0; step < steps; ++step)
        {
            // Add round ant

            s01 ^= RCON[step & 7];
            s03 ^= step;

            // ARXBOX layer
            {
                int rc = RCON[0];
                s00 += Integers.rotateRight(s01, 31);
                s01 ^= Integers.rotateRight(s00, 24);
                s00 ^= rc;
                s00 += Integers.rotateRight(s01, 17);
                s01 ^= Integers.rotateRight(s00, 17);
                s00 ^= rc;
                s00 += s01;
                s01 ^= Integers.rotateRight(s00, 31);
                s00 ^= rc;
                s00 += Integers.rotateRight(s01, 24);
                s01 ^= Integers.rotateRight(s00, 16);
                s00 ^= rc;
            }
            {
                int rc = RCON[1];
                s02 += Integers.rotateRight(s03, 31);
                s03 ^= Integers.rotateRight(s02, 24);
                s02 ^= rc;
                s02 += Integers.rotateRight(s03, 17);
                s03 ^= Integers.rotateRight(s02, 17);
                s02 ^= rc;
                s02 += s03;
                s03 ^= Integers.rotateRight(s02, 31);
                s02 ^= rc;
                s02 += Integers.rotateRight(s03, 24);
                s03 ^= Integers.rotateRight(s02, 16);
                s02 ^= rc;
            }
            {
                int rc = RCON[2];
                s04 += Integers.rotateRight(s05, 31);
                s05 ^= Integers.rotateRight(s04, 24);
                s04 ^= rc;
                s04 += Integers.rotateRight(s05, 17);
                s05 ^= Integers.rotateRight(s04, 17);
                s04 ^= rc;
                s04 += s05;
                s05 ^= Integers.rotateRight(s04, 31);
                s04 ^= rc;
                s04 += Integers.rotateRight(s05, 24);
                s05 ^= Integers.rotateRight(s04, 16);
                s04 ^= rc;
            }
            {
                int rc = RCON[3];
                s06 += Integers.rotateRight(s07, 31);
                s07 ^= Integers.rotateRight(s06, 24);
                s06 ^= rc;
                s06 += Integers.rotateRight(s07, 17);
                s07 ^= Integers.rotateRight(s06, 17);
                s06 ^= rc;
                s06 += s07;
                s07 ^= Integers.rotateRight(s06, 31);
                s06 ^= rc;
                s06 += Integers.rotateRight(s07, 24);
                s07 ^= Integers.rotateRight(s06, 16);
                s06 ^= rc;
            }
            {
                int rc = RCON[4];
                s08 += Integers.rotateRight(s09, 31);
                s09 ^= Integers.rotateRight(s08, 24);
                s08 ^= rc;
                s08 += Integers.rotateRight(s09, 17);
                s09 ^= Integers.rotateRight(s08, 17);
                s08 ^= rc;
                s08 += s09;
                s09 ^= Integers.rotateRight(s08, 31);
                s08 ^= rc;
                s08 += Integers.rotateRight(s09, 24);
                s09 ^= Integers.rotateRight(s08, 16);
                s08 ^= rc;
            }
            {
                int rc = RCON[5];
                s10 += Integers.rotateRight(s11, 31);
                s11 ^= Integers.rotateRight(s10, 24);
                s10 ^= rc;
                s10 += Integers.rotateRight(s11, 17);
                s11 ^= Integers.rotateRight(s10, 17);
                s10 ^= rc;
                s10 += s11;
                s11 ^= Integers.rotateRight(s10, 31);
                s10 ^= rc;
                s10 += Integers.rotateRight(s11, 24);
                s11 ^= Integers.rotateRight(s10, 16);
                s10 ^= rc;
            }
            {
                int rc = RCON[6];
                s12 += Integers.rotateRight(s13, 31);
                s13 ^= Integers.rotateRight(s12, 24);
                s12 ^= rc;
                s12 += Integers.rotateRight(s13, 17);
                s13 ^= Integers.rotateRight(s12, 17);
                s12 ^= rc;
                s12 += s13;
                s13 ^= Integers.rotateRight(s12, 31);
                s12 ^= rc;
                s12 += Integers.rotateRight(s13, 24);
                s13 ^= Integers.rotateRight(s12, 16);
                s12 ^= rc;
            }
            {
                int rc = RCON[7];
                s14 += Integers.rotateRight(s15, 31);
                s15 ^= Integers.rotateRight(s14, 24);
                s14 ^= rc;
                s14 += Integers.rotateRight(s15, 17);
                s15 ^= Integers.rotateRight(s14, 17);
                s14 ^= rc;
                s14 += s15;
                s15 ^= Integers.rotateRight(s14, 31);
                s14 ^= rc;
                s14 += Integers.rotateRight(s15, 24);
                s15 ^= Integers.rotateRight(s14, 16);
                s14 ^= rc;
            }

            // Linear layer

            int t0246 = ELL(s00 ^ s02 ^ s04 ^ s06);
            int t1357 = ELL(s01 ^ s03 ^ s05 ^ s07);

            int u00 = s00 ^ s08;
            int u01 = s01 ^ s09;
            int u02 = s02 ^ s10;
            int u03 = s03 ^ s11;
            int u04 = s04 ^ s12;
            int u05 = s05 ^ s13;
            int u06 = s06 ^ s14;
            int u07 = s07 ^ s15;

            s08 = s00;
            s09 = s01;
            s10 = s02;
            s11 = s03;
            s12 = s04;
            s13 = s05;
            s14 = s06;
            s15 = s07;

            s00 = u02 ^ t1357;
            s01 = u03 ^ t0246;
            s02 = u04 ^ t1357;
            s03 = u05 ^ t0246;
            s04 = u06 ^ t1357;
            s05 = u07 ^ t0246;
            s06 = u00 ^ t1357;
            s07 = u01 ^ t0246;
        }

        state[0] = s00;
        state[1] = s01;
        state[2] = s02;
        state[3] = s03;
        state[4] = s04;
        state[5] = s05;
        state[6] = s06;
        state[7] = s07;
        state[8] = s08;
        state[9] = s09;
        state[10] = s10;
        state[11] = s11;
        state[12] = s12;
        state[13] = s13;
        state[14] = s14;
        state[15] = s15;
    }

    public static void sparkle_opt16(SparkleDigest.Friend friend, int[] state, int steps)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by SparkleDigest");
        }

        sparkle_opt16(state, steps);
    }
}
