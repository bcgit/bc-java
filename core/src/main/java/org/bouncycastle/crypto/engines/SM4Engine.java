package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

/**
 * SM4 Block Cipher - SM4 is a 128 bit block cipher with a 128 bit key.
 * <p>
 *     The implementation here is based on the document <a href="http://eprint.iacr.org/2008/329.pdf">http://eprint.iacr.org/2008/329.pdf</a>
 *     by Whitfield Diffie and George Ledin, which is a translation of Prof. LU Shu-wang's original standard.
 * </p>
 */
public class SM4Engine
    implements BlockCipher
{
    private static final int BLOCK_SIZE = 16;

    private final static byte[] Sbox =
    {
        (byte)0xd6, (byte)0x90, (byte)0xe9, (byte)0xfe, (byte)0xcc, (byte)0xe1, (byte)0x3d, (byte)0xb7, (byte)0x16, (byte)0xb6, (byte)0x14, (byte)0xc2, (byte)0x28, (byte)0xfb, (byte)0x2c, (byte)0x05,
        (byte)0x2b, (byte)0x67, (byte)0x9a, (byte)0x76, (byte)0x2a, (byte)0xbe, (byte)0x04, (byte)0xc3, (byte)0xaa, (byte)0x44, (byte)0x13, (byte)0x26, (byte)0x49, (byte)0x86, (byte)0x06, (byte)0x99,
        (byte)0x9c, (byte)0x42, (byte)0x50, (byte)0xf4, (byte)0x91, (byte)0xef, (byte)0x98, (byte)0x7a, (byte)0x33, (byte)0x54, (byte)0x0b, (byte)0x43, (byte)0xed, (byte)0xcf, (byte)0xac, (byte)0x62,
        (byte)0xe4, (byte)0xb3, (byte)0x1c, (byte)0xa9, (byte)0xc9, (byte)0x08, (byte)0xe8, (byte)0x95, (byte)0x80, (byte)0xdf, (byte)0x94, (byte)0xfa, (byte)0x75, (byte)0x8f, (byte)0x3f, (byte)0xa6,
        (byte)0x47, (byte)0x07, (byte)0xa7, (byte)0xfc, (byte)0xf3, (byte)0x73, (byte)0x17, (byte)0xba, (byte)0x83, (byte)0x59, (byte)0x3c, (byte)0x19, (byte)0xe6, (byte)0x85, (byte)0x4f, (byte)0xa8,
        (byte)0x68, (byte)0x6b, (byte)0x81, (byte)0xb2, (byte)0x71, (byte)0x64, (byte)0xda, (byte)0x8b, (byte)0xf8, (byte)0xeb, (byte)0x0f, (byte)0x4b, (byte)0x70, (byte)0x56, (byte)0x9d, (byte)0x35,
        (byte)0x1e, (byte)0x24, (byte)0x0e, (byte)0x5e, (byte)0x63, (byte)0x58, (byte)0xd1, (byte)0xa2, (byte)0x25, (byte)0x22, (byte)0x7c, (byte)0x3b, (byte)0x01, (byte)0x21, (byte)0x78, (byte)0x87,
        (byte)0xd4, (byte)0x00, (byte)0x46, (byte)0x57, (byte)0x9f, (byte)0xd3, (byte)0x27, (byte)0x52, (byte)0x4c, (byte)0x36, (byte)0x02, (byte)0xe7, (byte)0xa0, (byte)0xc4, (byte)0xc8, (byte)0x9e,
        (byte)0xea, (byte)0xbf, (byte)0x8a, (byte)0xd2, (byte)0x40, (byte)0xc7, (byte)0x38, (byte)0xb5, (byte)0xa3, (byte)0xf7, (byte)0xf2, (byte)0xce, (byte)0xf9, (byte)0x61, (byte)0x15, (byte)0xa1,
        (byte)0xe0, (byte)0xae, (byte)0x5d, (byte)0xa4, (byte)0x9b, (byte)0x34, (byte)0x1a, (byte)0x55, (byte)0xad, (byte)0x93, (byte)0x32, (byte)0x30, (byte)0xf5, (byte)0x8c, (byte)0xb1, (byte)0xe3,
        (byte)0x1d, (byte)0xf6, (byte)0xe2, (byte)0x2e, (byte)0x82, (byte)0x66, (byte)0xca, (byte)0x60, (byte)0xc0, (byte)0x29, (byte)0x23, (byte)0xab, (byte)0x0d, (byte)0x53, (byte)0x4e, (byte)0x6f,
        (byte)0xd5, (byte)0xdb, (byte)0x37, (byte)0x45, (byte)0xde, (byte)0xfd, (byte)0x8e, (byte)0x2f, (byte)0x03, (byte)0xff, (byte)0x6a, (byte)0x72, (byte)0x6d, (byte)0x6c, (byte)0x5b, (byte)0x51,
        (byte)0x8d, (byte)0x1b, (byte)0xaf, (byte)0x92, (byte)0xbb, (byte)0xdd, (byte)0xbc, (byte)0x7f, (byte)0x11, (byte)0xd9, (byte)0x5c, (byte)0x41, (byte)0x1f, (byte)0x10, (byte)0x5a, (byte)0xd8,
        (byte)0x0a, (byte)0xc1, (byte)0x31, (byte)0x88, (byte)0xa5, (byte)0xcd, (byte)0x7b, (byte)0xbd, (byte)0x2d, (byte)0x74, (byte)0xd0, (byte)0x12, (byte)0xb8, (byte)0xe5, (byte)0xb4, (byte)0xb0,
        (byte)0x89, (byte)0x69, (byte)0x97, (byte)0x4a, (byte)0x0c, (byte)0x96, (byte)0x77, (byte)0x7e, (byte)0x65, (byte)0xb9, (byte)0xf1, (byte)0x09, (byte)0xc5, (byte)0x6e, (byte)0xc6, (byte)0x84,
        (byte)0x18, (byte)0xf0, (byte)0x7d, (byte)0xec, (byte)0x3a, (byte)0xdc, (byte)0x4d, (byte)0x20, (byte)0x79, (byte)0xee, (byte)0x5f, (byte)0x3e, (byte)0xd7, (byte)0xcb, (byte)0x39, (byte)0x48
    };

    private final static int[] CK =
    {
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };

    private final static int[] FK =
    {
        0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
    };

    private final int[] X = new int[4];

    private int[] rk;

    private int rotateLeft(
        int x,
        int bits)
    {
        return (x << bits) | (x >>> -bits);
    }

    // non-linear substitution tau.
    private int tau(
        int A)
    {
        int b0 = Sbox[(A >> 24) & 0xff] & 0xff;
        int b1 = Sbox[(A >> 16) & 0xff] & 0xff;
        int b2 = Sbox[(A >> 8) & 0xff] & 0xff;
        int b3 = Sbox[A & 0xff] & 0xff;

        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    private int L_ap(
        int B)
    {
        return (B ^ (rotateLeft(B, 13)) ^ (rotateLeft(B, 23)));
    }

    private int T_ap(
        int Z)
    {
        return L_ap(tau(Z));
    }

    // Key expansion
    private int[] expandKey(boolean forEncryption, byte[] key)
    {
        int[] rk = new int[32];
        int[] MK = new int[4];

        MK[0] = Pack.bigEndianToInt(key, 0);
        MK[1] = Pack.bigEndianToInt(key, 4);
        MK[2] = Pack.bigEndianToInt(key, 8);
        MK[3] = Pack.bigEndianToInt(key, 12);

        int i;
        int[] K = new int[4];
        K[0] = MK[0] ^ FK[0];
        K[1] = MK[1] ^ FK[1];
        K[2] = MK[2] ^ FK[2];
        K[3] = MK[3] ^ FK[3];

        if (forEncryption)
        {
            rk[0] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
            rk[1] = K[1] ^ T_ap(K[2] ^ K[3] ^ rk[0] ^ CK[1]);
            rk[2] = K[2] ^ T_ap(K[3] ^ rk[0] ^ rk[1] ^ CK[2]);
            rk[3] = K[3] ^ T_ap(rk[0] ^ rk[1] ^ rk[2] ^ CK[3]);
            for (i = 4; i < 32; i++)
            {
                rk[i] = rk[i - 4] ^ T_ap(rk[i - 3] ^ rk[i - 2] ^ rk[i - 1] ^ CK[i]);
            }
        }
        else
        {
            rk[31] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
            rk[30] = K[1] ^ T_ap(K[2] ^ K[3] ^ rk[31] ^ CK[1]);
            rk[29] = K[2] ^ T_ap(K[3] ^ rk[31] ^ rk[30] ^ CK[2]);
            rk[28] = K[3] ^ T_ap(rk[31] ^ rk[30] ^ rk[29] ^ CK[3]);
            for (i = 27; i >= 0; i--)
            {
                rk[i] = rk[i + 4] ^ T_ap(rk[i + 3] ^ rk[i + 2] ^ rk[i + 1] ^ CK[31 - i]);
            }
        }

        return rk;
    }


    // Linear substitution L
    private int L(int B)
    {
        int C;
        C = (B ^ (rotateLeft(B, 2)) ^ (rotateLeft(B, 10)) ^ (rotateLeft(B,
            18)) ^ (rotateLeft(B, 24)));
        return C;
    }

    // Mixer-substitution T
    private int T(int Z)
    {
        return L(tau(Z));
    }

    // The round functions
    private int F0(int[] X, int rk)
    {
        return (X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ rk));
    }

    private int F1(int[] X, int rk)
    {
        return (X[1] ^ T(X[2] ^ X[3] ^ X[0] ^ rk));
    }

    private int F2(int[] X, int rk)
    {
        return (X[2] ^ T(X[3] ^ X[0] ^ X[1] ^ rk));
    }

    private int F3(int[] X, int rk)
    {
        return (X[3] ^ T(X[0] ^ X[1] ^ X[2] ^ rk));
    }

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof KeyParameter)
        {
            byte[] key = ((KeyParameter)params).getKey();

            if (key.length != 16)
            {
                throw new IllegalArgumentException("SM4 requires a 128 bit key");
            }

            rk = expandKey(forEncryption, key);
        }
        else
        {
            throw new IllegalArgumentException("invalid parameter passed to SM4 init - " + params.getClass().getName());
        }
    }

    public String getAlgorithmName()
    {
        return "SM4";
    }

    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (rk == null)
        {
            throw new IllegalStateException("SM4 not initialised");
        }

        if ((inOff + BLOCK_SIZE) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if ((outOff + BLOCK_SIZE) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        X[0] = Pack.bigEndianToInt(in, inOff);
        X[1] = Pack.bigEndianToInt(in, inOff + 4);
        X[2] = Pack.bigEndianToInt(in, inOff + 8);
        X[3] = Pack.bigEndianToInt(in, inOff + 12);

        int i;

        for (i = 0; i < 32; i += 4)
        {
            X[0] = F0(X, rk[i]);
            X[1] = F1(X, rk[i + 1]);
            X[2] = F2(X, rk[i + 2]);
            X[3] = F3(X, rk[i + 3]);
        }

        Pack.intToBigEndian(X[3], out, outOff);
        Pack.intToBigEndian(X[2], out, outOff + 4);
        Pack.intToBigEndian(X[1], out, outOff + 8);
        Pack.intToBigEndian(X[0], out, outOff + 12);

        return BLOCK_SIZE;
    }

    public void reset()
    {
    }
}
