package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Memoable;

/**
 * Zuc128Engine implementation.
 * Based on https://www.gsma.com/aboutus/wp-content/uploads/2014/12/eea3eia3zucv16.pdf
 */
public class Zuc128CoreEngine
    implements StreamCipher, Memoable
{
    /* the s-boxes */
    private static final byte[] S0 = new byte[]{
        (byte)0x3e, (byte)0x72, (byte)0x5b, (byte)0x47, (byte)0xca, (byte)0xe0, (byte)0x00, (byte)0x33, (byte)0x04, (byte)0xd1, (byte)0x54, (byte)0x98, (byte)0x09, (byte)0xb9, (byte)0x6d, (byte)0xcb,
        (byte)0x7b, (byte)0x1b, (byte)0xf9, (byte)0x32, (byte)0xaf, (byte)0x9d, (byte)0x6a, (byte)0xa5, (byte)0xb8, (byte)0x2d, (byte)0xfc, (byte)0x1d, (byte)0x08, (byte)0x53, (byte)0x03, (byte)0x90,
        (byte)0x4d, (byte)0x4e, (byte)0x84, (byte)0x99, (byte)0xe4, (byte)0xce, (byte)0xd9, (byte)0x91, (byte)0xdd, (byte)0xb6, (byte)0x85, (byte)0x48, (byte)0x8b, (byte)0x29, (byte)0x6e, (byte)0xac,
        (byte)0xcd, (byte)0xc1, (byte)0xf8, (byte)0x1e, (byte)0x73, (byte)0x43, (byte)0x69, (byte)0xc6, (byte)0xb5, (byte)0xbd, (byte)0xfd, (byte)0x39, (byte)0x63, (byte)0x20, (byte)0xd4, (byte)0x38,
        (byte)0x76, (byte)0x7d, (byte)0xb2, (byte)0xa7, (byte)0xcf, (byte)0xed, (byte)0x57, (byte)0xc5, (byte)0xf3, (byte)0x2c, (byte)0xbb, (byte)0x14, (byte)0x21, (byte)0x06, (byte)0x55, (byte)0x9b,
        (byte)0xe3, (byte)0xef, (byte)0x5e, (byte)0x31, (byte)0x4f, (byte)0x7f, (byte)0x5a, (byte)0xa4, (byte)0x0d, (byte)0x82, (byte)0x51, (byte)0x49, (byte)0x5f, (byte)0xba, (byte)0x58, (byte)0x1c,
        (byte)0x4a, (byte)0x16, (byte)0xd5, (byte)0x17, (byte)0xa8, (byte)0x92, (byte)0x24, (byte)0x1f, (byte)0x8c, (byte)0xff, (byte)0xd8, (byte)0xae, (byte)0x2e, (byte)0x01, (byte)0xd3, (byte)0xad,
        (byte)0x3b, (byte)0x4b, (byte)0xda, (byte)0x46, (byte)0xeb, (byte)0xc9, (byte)0xde, (byte)0x9a, (byte)0x8f, (byte)0x87, (byte)0xd7, (byte)0x3a, (byte)0x80, (byte)0x6f, (byte)0x2f, (byte)0xc8,
        (byte)0xb1, (byte)0xb4, (byte)0x37, (byte)0xf7, (byte)0x0a, (byte)0x22, (byte)0x13, (byte)0x28, (byte)0x7c, (byte)0xcc, (byte)0x3c, (byte)0x89, (byte)0xc7, (byte)0xc3, (byte)0x96, (byte)0x56,
        (byte)0x07, (byte)0xbf, (byte)0x7e, (byte)0xf0, (byte)0x0b, (byte)0x2b, (byte)0x97, (byte)0x52, (byte)0x35, (byte)0x41, (byte)0x79, (byte)0x61, (byte)0xa6, (byte)0x4c, (byte)0x10, (byte)0xfe,
        (byte)0xbc, (byte)0x26, (byte)0x95, (byte)0x88, (byte)0x8a, (byte)0xb0, (byte)0xa3, (byte)0xfb, (byte)0xc0, (byte)0x18, (byte)0x94, (byte)0xf2, (byte)0xe1, (byte)0xe5, (byte)0xe9, (byte)0x5d,
        (byte)0xd0, (byte)0xdc, (byte)0x11, (byte)0x66, (byte)0x64, (byte)0x5c, (byte)0xec, (byte)0x59, (byte)0x42, (byte)0x75, (byte)0x12, (byte)0xf5, (byte)0x74, (byte)0x9c, (byte)0xaa, (byte)0x23,
        (byte)0x0e, (byte)0x86, (byte)0xab, (byte)0xbe, (byte)0x2a, (byte)0x02, (byte)0xe7, (byte)0x67, (byte)0xe6, (byte)0x44, (byte)0xa2, (byte)0x6c, (byte)0xc2, (byte)0x93, (byte)0x9f, (byte)0xf1,
        (byte)0xf6, (byte)0xfa, (byte)0x36, (byte)0xd2, (byte)0x50, (byte)0x68, (byte)0x9e, (byte)0x62, (byte)0x71, (byte)0x15, (byte)0x3d, (byte)0xd6, (byte)0x40, (byte)0xc4, (byte)0xe2, (byte)0x0f,
        (byte)0x8e, (byte)0x83, (byte)0x77, (byte)0x6b, (byte)0x25, (byte)0x05, (byte)0x3f, (byte)0x0c, (byte)0x30, (byte)0xea, (byte)0x70, (byte)0xb7, (byte)0xa1, (byte)0xe8, (byte)0xa9, (byte)0x65,
        (byte)0x8d, (byte)0x27, (byte)0x1a, (byte)0xdb, (byte)0x81, (byte)0xb3, (byte)0xa0, (byte)0xf4, (byte)0x45, (byte)0x7a, (byte)0x19, (byte)0xdf, (byte)0xee, (byte)0x78, (byte)0x34, (byte)0x60
    };

    private static final byte[] S1 = new byte[]{
        (byte)0x55, (byte)0xc2, (byte)0x63, (byte)0x71, (byte)0x3b, (byte)0xc8, (byte)0x47, (byte)0x86, (byte)0x9f, (byte)0x3c, (byte)0xda, (byte)0x5b, (byte)0x29, (byte)0xaa, (byte)0xfd, (byte)0x77,
        (byte)0x8c, (byte)0xc5, (byte)0x94, (byte)0x0c, (byte)0xa6, (byte)0x1a, (byte)0x13, (byte)0x00, (byte)0xe3, (byte)0xa8, (byte)0x16, (byte)0x72, (byte)0x40, (byte)0xf9, (byte)0xf8, (byte)0x42,
        (byte)0x44, (byte)0x26, (byte)0x68, (byte)0x96, (byte)0x81, (byte)0xd9, (byte)0x45, (byte)0x3e, (byte)0x10, (byte)0x76, (byte)0xc6, (byte)0xa7, (byte)0x8b, (byte)0x39, (byte)0x43, (byte)0xe1,
        (byte)0x3a, (byte)0xb5, (byte)0x56, (byte)0x2a, (byte)0xc0, (byte)0x6d, (byte)0xb3, (byte)0x05, (byte)0x22, (byte)0x66, (byte)0xbf, (byte)0xdc, (byte)0x0b, (byte)0xfa, (byte)0x62, (byte)0x48,
        (byte)0xdd, (byte)0x20, (byte)0x11, (byte)0x06, (byte)0x36, (byte)0xc9, (byte)0xc1, (byte)0xcf, (byte)0xf6, (byte)0x27, (byte)0x52, (byte)0xbb, (byte)0x69, (byte)0xf5, (byte)0xd4, (byte)0x87,
        (byte)0x7f, (byte)0x84, (byte)0x4c, (byte)0xd2, (byte)0x9c, (byte)0x57, (byte)0xa4, (byte)0xbc, (byte)0x4f, (byte)0x9a, (byte)0xdf, (byte)0xfe, (byte)0xd6, (byte)0x8d, (byte)0x7a, (byte)0xeb,
        (byte)0x2b, (byte)0x53, (byte)0xd8, (byte)0x5c, (byte)0xa1, (byte)0x14, (byte)0x17, (byte)0xfb, (byte)0x23, (byte)0xd5, (byte)0x7d, (byte)0x30, (byte)0x67, (byte)0x73, (byte)0x08, (byte)0x09,
        (byte)0xee, (byte)0xb7, (byte)0x70, (byte)0x3f, (byte)0x61, (byte)0xb2, (byte)0x19, (byte)0x8e, (byte)0x4e, (byte)0xe5, (byte)0x4b, (byte)0x93, (byte)0x8f, (byte)0x5d, (byte)0xdb, (byte)0xa9,
        (byte)0xad, (byte)0xf1, (byte)0xae, (byte)0x2e, (byte)0xcb, (byte)0x0d, (byte)0xfc, (byte)0xf4, (byte)0x2d, (byte)0x46, (byte)0x6e, (byte)0x1d, (byte)0x97, (byte)0xe8, (byte)0xd1, (byte)0xe9,
        (byte)0x4d, (byte)0x37, (byte)0xa5, (byte)0x75, (byte)0x5e, (byte)0x83, (byte)0x9e, (byte)0xab, (byte)0x82, (byte)0x9d, (byte)0xb9, (byte)0x1c, (byte)0xe0, (byte)0xcd, (byte)0x49, (byte)0x89,
        (byte)0x01, (byte)0xb6, (byte)0xbd, (byte)0x58, (byte)0x24, (byte)0xa2, (byte)0x5f, (byte)0x38, (byte)0x78, (byte)0x99, (byte)0x15, (byte)0x90, (byte)0x50, (byte)0xb8, (byte)0x95, (byte)0xe4,
        (byte)0xd0, (byte)0x91, (byte)0xc7, (byte)0xce, (byte)0xed, (byte)0x0f, (byte)0xb4, (byte)0x6f, (byte)0xa0, (byte)0xcc, (byte)0xf0, (byte)0x02, (byte)0x4a, (byte)0x79, (byte)0xc3, (byte)0xde,
        (byte)0xa3, (byte)0xef, (byte)0xea, (byte)0x51, (byte)0xe6, (byte)0x6b, (byte)0x18, (byte)0xec, (byte)0x1b, (byte)0x2c, (byte)0x80, (byte)0xf7, (byte)0x74, (byte)0xe7, (byte)0xff, (byte)0x21,
        (byte)0x5a, (byte)0x6a, (byte)0x54, (byte)0x1e, (byte)0x41, (byte)0x31, (byte)0x92, (byte)0x35, (byte)0xc4, (byte)0x33, (byte)0x07, (byte)0x0a, (byte)0xba, (byte)0x7e, (byte)0x0e, (byte)0x34,
        (byte)0x88, (byte)0xb1, (byte)0x98, (byte)0x7c, (byte)0xf3, (byte)0x3d, (byte)0x60, (byte)0x6c, (byte)0x7b, (byte)0xca, (byte)0xd3, (byte)0x1f, (byte)0x32, (byte)0x65, (byte)0x04, (byte)0x28,
        (byte)0x64, (byte)0xbe, (byte)0x85, (byte)0x9b, (byte)0x2f, (byte)0x59, (byte)0x8a, (byte)0xd7, (byte)0xb0, (byte)0x25, (byte)0xac, (byte)0xaf, (byte)0x12, (byte)0x03, (byte)0xe2, (byte)0xf2
    };

    /* the constants D */
    private static final short[] EK_d = new short[]{
        0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
        0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
    };

    /**
     * State.
     */
    private final int[] LFSR = new int[16];
    private final int[] F = new int[2];
    private final int[] BRC = new int[4];

    /**
     * index of next byte in keyStream.
     */
    private int theIndex;

    /**
     * Advanced stream.
     */
    private final byte[] keyStream = new byte[4];   // Integer.BYTES

    /**
     * The iterations.
     */
    private int theIterations;

    /**
     * Reset state.
     */
    private Zuc128CoreEngine theResetState;

    /**
     * Constructor.
     */
    protected Zuc128CoreEngine()
    {
    }

    /**
     * Constructor.
     *
     * @param pSource the source engine
     */
    protected Zuc128CoreEngine(final Zuc128CoreEngine pSource)
    {
        reset(pSource);
    }

    /**
     * initialise a Snow3G cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params        the parameters required to set up the cipher.
     * @throws IllegalArgumentException if the params argument is inappropriate.
     */
    public void init(final boolean forEncryption,
                     final CipherParameters params)
    {
        /*
         * encryption and decryption is completely symmetrical, so the 'forEncryption' is
         * irrelevant. (Like 90% of stream ciphers)
         */

        /* Determine parameters */
        CipherParameters myParams = params;
        byte[] newKey = null;
        byte[] newIV = null;
        if ((myParams instanceof ParametersWithIV))
        {
            final ParametersWithIV ivParams = (ParametersWithIV)myParams;
            newIV = ivParams.getIV();
            myParams = ivParams.getParameters();
        }
        if (myParams instanceof KeyParameter)
        {
            final KeyParameter keyParam = (KeyParameter)myParams;
            newKey = keyParam.getKey();
        }

        /* Initialise engine and mark as initialised */
        theIndex = 0;
        theIterations = 0;
        setKeyAndIV(newKey, newIV);

        /* Save reset state */
        theResetState = (Zuc128CoreEngine)copy();
    }

    /**
     * Obtain Max iterations.
     *
     * @return the maximum iterations
     */
    protected int getMaxIterations()
    {
        return 2047;
    }

    /**
     * Obtain Algorithm Name.
     *
     * @return the name
     */
    public String getAlgorithmName()
    {
        return "Zuc-128";
    }

    /**
     * Process bytes.
     *
     * @param in     the input buffer
     * @param inOff  the starting offset in the input buffer
     * @param len    the length of data in the input buffer
     * @param out    the output buffer
     * @param outOff the starting offset in the output buffer
     * @return the number of bytes returned in the output buffer
     */
    public int processBytes(final byte[] in,
                            final int inOff,
                            final int len,
                            final byte[] out,
                            final int outOff)
    {
        /* Check for errors */
        if (theResetState == null)
        {
            throw new IllegalStateException(getAlgorithmName() + " not initialised");
        }
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        if ((outOff + len) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        /* Loop through the input bytes */
        for (int i = 0; i < len; i++)
        {
            out[i + outOff] = returnByte(in[i + inOff]);
        }
        return len;
    }

    /**
     * Reset the engine.
     */
    public void reset()
    {
        if (theResetState != null)
        {
            reset(theResetState);
        }
    }

    /**
     * Process single byte.
     *
     * @param in the input byte
     * @return the output byte
     */
    public byte returnByte(final byte in)
    {
        /* Make the keyStream if required */
        if (theIndex == 0)
        {
            makeKeyStream();
        }

        /* Map the next byte and adjust index */
        final byte out = (byte)(keyStream[theIndex] ^ in);
        theIndex = (theIndex + 1) % 4; // Integer.BYTES

        /* Return the mapped character */
        return out;
    }

    /**
     * Encode a 32-bit value into a buffer (little-endian).
     *
     * @param val the value to encode
     * @param buf the output buffer
     * @param off the output offset
     */
    public static void encode32be(int val, byte[] buf, int off)
    {
        buf[off] = (byte)(val >> 24);
        buf[off + 1] = (byte)(val >> 16);
        buf[off + 2] = (byte)(val >> 8);
        buf[off + 3] = (byte)val;
    }

    /* ����������������������- */

    /**
     * Modular add c = a + b mod (2^31 � 1).
     *
     * @param a value A
     * @param b value B
     * @return the result
     */
    private int AddM(final int a, final int b)
    {
        final int c = a + b;
        return (c & 0x7FFFFFFF) + (c >>> 31);
    }

    /**
     * Multiply by power of two.
     *
     * @param x input value
     * @param k the power of two
     * @return the result
     */
    private static int MulByPow2(final int x, final int k)
    {
        return ((((x) << k) | ((x) >>> (31 - k))) & 0x7FFFFFFF);
    }

    /**
     * LFSR with initialisation mode.
     *
     * @param u
     */
    private void LFSRWithInitialisationMode(final int u)
    {
        int f = LFSR[0];
        int v = MulByPow2(LFSR[0], 8);
        f = AddM(f, v);
        v = MulByPow2(LFSR[4], 20);
        f = AddM(f, v);
        v = MulByPow2(LFSR[10], 21);
        f = AddM(f, v);
        v = MulByPow2(LFSR[13], 17);
        f = AddM(f, v);
        v = MulByPow2(LFSR[15], 15);
        f = AddM(f, v);
        f = AddM(f, u);

        /* update the state */
        LFSR[0] = LFSR[1];
        LFSR[1] = LFSR[2];
        LFSR[2] = LFSR[3];
        LFSR[3] = LFSR[4];
        LFSR[4] = LFSR[5];
        LFSR[5] = LFSR[6];
        LFSR[6] = LFSR[7];
        LFSR[7] = LFSR[8];
        LFSR[8] = LFSR[9];
        LFSR[9] = LFSR[10];
        LFSR[10] = LFSR[11];
        LFSR[11] = LFSR[12];
        LFSR[12] = LFSR[13];
        LFSR[13] = LFSR[14];
        LFSR[14] = LFSR[15];
        LFSR[15] = f;
    }

    /**
     * LFSR with work mode.
     */
    private void LFSRWithWorkMode()
    {
        int f, v;
        f = LFSR[0];
        v = MulByPow2(LFSR[0], 8);
        f = AddM(f, v);
        v = MulByPow2(LFSR[4], 20);
        f = AddM(f, v);
        v = MulByPow2(LFSR[10], 21);
        f = AddM(f, v);
        v = MulByPow2(LFSR[13], 17);
        f = AddM(f, v);
        v = MulByPow2(LFSR[15], 15);
        f = AddM(f, v);

        /* update the state */
        LFSR[0] = LFSR[1];
        LFSR[1] = LFSR[2];
        LFSR[2] = LFSR[3];
        LFSR[3] = LFSR[4];
        LFSR[4] = LFSR[5];
        LFSR[5] = LFSR[6];
        LFSR[6] = LFSR[7];
        LFSR[7] = LFSR[8];
        LFSR[8] = LFSR[9];
        LFSR[9] = LFSR[10];
        LFSR[10] = LFSR[11];
        LFSR[11] = LFSR[12];
        LFSR[12] = LFSR[13];
        LFSR[13] = LFSR[14];
        LFSR[14] = LFSR[15];
        LFSR[15] = f;
    }

    /**
     * BitReorganization.
     */
    private void BitReorganization()
    {
        BRC[0] = ((LFSR[15] & 0x7FFF8000) << 1) | (LFSR[14] & 0xFFFF);
        BRC[1] = ((LFSR[11] & 0xFFFF) << 16) | (LFSR[9] >>> 15);
        BRC[2] = ((LFSR[7] & 0xFFFF) << 16) | (LFSR[5] >>> 15);
        BRC[3] = ((LFSR[2] & 0xFFFF) << 16) | (LFSR[0] >>> 15);
    }

    /**
     * Rotate integer.
     *
     * @param a the integer
     * @param k the shift
     * @return the result
     */
    static int ROT(int a, int k)
    {
        return (((a) << k) | ((a) >>> (32 - k)));
    }

    /**
     * L1.
     *
     * @param X the input integer.
     * @return the result
     */
    private static int L1(final int X)
    {
        return (X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24));
    }

    /**
     * L2.
     *
     * @param X the input integer.
     * @return the result
     */
    private static int L2(final int X)
    {
        return (X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30));
    }

    /**
     * Build a 32-bit integer from constituent parts.
     *
     * @param a part A
     * @param b part B
     * @param c part C
     * @param d part D
     * @return the built integer
     */
    private static int MAKEU32(final byte a,
                               final byte b,
                               final byte c,
                               final byte d)
    {
        return (((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFF) << 8) | ((d & 0xFF)));
    }

    /**
     * F.
     */
    int F()
    {
        int W, W1, W2, u, v;
        W = (BRC[0] ^ F[0]) + F[1];
        W1 = F[0] + BRC[1];
        W2 = F[1] ^ BRC[2];
        u = L1((W1 << 16) | (W2 >>> 16));
        v = L2((W2 << 16) | (W1 >>> 16));
        F[0] = MAKEU32(S0[u >>> 24], S1[(u >>> 16) & 0xFF],
            S0[(u >>> 8) & 0xFF], S1[u & 0xFF]);
        F[1] = MAKEU32(S0[v >>> 24], S1[(v >>> 16) & 0xFF],
            S0[(v >>> 8) & 0xFF], S1[v & 0xFF]);
        return W;
    }

    /**
     * Build a 31-bit integer from constituent parts.
     *
     * @param a part A
     * @param b part B
     * @param c part C
     * @return the built integer
     */
    private static int MAKEU31(final byte a,
                               final short b,
                               final byte c)
    {
        return (((a & 0xFF) << 23) | ((b & 0xFFFF) << 8) | (c & 0xFF));
    }

    /**
     * Process key and IV into LFSR.
     *
     * @param pLFSR the LFSR
     * @param k     the key
     * @param iv    the iv
     */
    protected void setKeyAndIV(final int[] pLFSR,
                               final byte[] k,
                               final byte[] iv)
    {
        /* Check lengths */
        if (k == null || k.length != 16)
        {
            throw new IllegalArgumentException("A key of 16 bytes is needed");
        }
        if (iv == null || iv.length != 16)
        {
            throw new IllegalArgumentException("An IV of 16 bytes is needed");
        }

        /* expand key */
        LFSR[0] = MAKEU31(k[0], EK_d[0], iv[0]);
        LFSR[1] = MAKEU31(k[1], EK_d[1], iv[1]);
        LFSR[2] = MAKEU31(k[2], EK_d[2], iv[2]);
        LFSR[3] = MAKEU31(k[3], EK_d[3], iv[3]);
        LFSR[4] = MAKEU31(k[4], EK_d[4], iv[4]);
        LFSR[5] = MAKEU31(k[5], EK_d[5], iv[5]);
        LFSR[6] = MAKEU31(k[6], EK_d[6], iv[6]);
        LFSR[7] = MAKEU31(k[7], EK_d[7], iv[7]);
        LFSR[8] = MAKEU31(k[8], EK_d[8], iv[8]);
        LFSR[9] = MAKEU31(k[9], EK_d[9], iv[9]);
        LFSR[10] = MAKEU31(k[10], EK_d[10], iv[10]);
        LFSR[11] = MAKEU31(k[11], EK_d[11], iv[11]);
        LFSR[12] = MAKEU31(k[12], EK_d[12], iv[12]);
        LFSR[13] = MAKEU31(k[13], EK_d[13], iv[13]);
        LFSR[14] = MAKEU31(k[14], EK_d[14], iv[14]);
        LFSR[15] = MAKEU31(k[15], EK_d[15], iv[15]);
    }

    /**
     * Process key and IV.
     *
     * @param k  the key
     * @param iv the IV
     */
    private void setKeyAndIV(final byte[] k,
                             final byte[] iv)
    {
        /* Initialise LFSR */
        setKeyAndIV(LFSR, k, iv);

        /* set F_R1 and F_R2 to zero */
        F[0] = 0;
        F[1] = 0;
        int nCount = 32;
        while (nCount > 0)
        {
            BitReorganization();
            final int w = F();
            LFSRWithInitialisationMode(w >>> 1);
            nCount--;
        }
        BitReorganization();
        F(); /* discard the output of F */
        LFSRWithWorkMode();
    }

    /**
     * Create the next byte keyStream.
     */
    private void makeKeyStream()
    {
        encode32be(makeKeyStreamWord(), keyStream, 0);
    }

    /**
     * Create the next keyStream word.
     *
     * @return the next word
     */
    protected int makeKeyStreamWord()
    {
        if (theIterations++ >= getMaxIterations())
        {
            throw new IllegalStateException("Too much data processed by singleKey/IV");
        }
        BitReorganization();
        final int result = F() ^ BRC[3];
        LFSRWithWorkMode();
        return result;
    }

    /**
     * Create a copy of the engine.
     *
     * @return the copy
     */
    public Memoable copy()
    {
        return new Zuc128CoreEngine(this);
    }

    /**
     * Reset from saved engine state.
     *
     * @param pState the state to restore
     */
    public void reset(final Memoable pState)
    {
        final Zuc128CoreEngine e = (Zuc128CoreEngine)pState;
        System.arraycopy(e.LFSR, 0, LFSR, 0, LFSR.length);
        System.arraycopy(e.F, 0, F, 0, F.length);
        System.arraycopy(e.BRC, 0, BRC, 0, BRC.length);
        System.arraycopy(e.keyStream, 0, keyStream, 0, keyStream.length);
        theIndex = e.theIndex;
        theIterations = e.theIterations;
        theResetState = e;
    }
}
