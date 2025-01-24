package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

/**
 * Romulus v1.3, based on the current round 3 submission, https://romulusae.github.io/romulus/
 * Reference C implementation: https://github.com/romulusae/romulus
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
 */

public class RomulusDigest
    extends BufferBaseDigest
{
    byte[] h = new byte[16];
    byte[] g = new byte[16];
    /*
     * This file includes only the encryption function of SKINNY-128-384+ as required by Romulus-v1.3
     */
// Packing of data is done as follows (state[i][j] stands for row i and column j):
// 0  1  2  3
// 4  5  6  7
// 8  9 10 11
//12 13 14 15

    // 8-bit Sbox
    private final byte[] sbox_8 =
        {
            (byte)0x65, (byte)0x4c, (byte)0x6a, (byte)0x42, (byte)0x4b, (byte)0x63, (byte)0x43, (byte)0x6b, (byte)0x55,
            (byte)0x75, (byte)0x5a, (byte)0x7a, (byte)0x53, (byte)0x73, (byte)0x5b, (byte)0x7b, (byte)0x35, (byte)0x8c,
            (byte)0x3a, (byte)0x81, (byte)0x89, (byte)0x33, (byte)0x80, (byte)0x3b, (byte)0x95, (byte)0x25, (byte)0x98,
            (byte)0x2a, (byte)0x90, (byte)0x23, (byte)0x99, (byte)0x2b, (byte)0xe5, (byte)0xcc, (byte)0xe8, (byte)0xc1,
            (byte)0xc9, (byte)0xe0, (byte)0xc0, (byte)0xe9, (byte)0xd5, (byte)0xf5, (byte)0xd8, (byte)0xf8, (byte)0xd0,
            (byte)0xf0, (byte)0xd9, (byte)0xf9, (byte)0xa5, (byte)0x1c, (byte)0xa8, (byte)0x12, (byte)0x1b, (byte)0xa0,
            (byte)0x13, (byte)0xa9, (byte)0x05, (byte)0xb5, (byte)0x0a, (byte)0xb8, (byte)0x03, (byte)0xb0, (byte)0x0b,
            (byte)0xb9, (byte)0x32, (byte)0x88, (byte)0x3c, (byte)0x85, (byte)0x8d, (byte)0x34, (byte)0x84, (byte)0x3d,
            (byte)0x91, (byte)0x22, (byte)0x9c, (byte)0x2c, (byte)0x94, (byte)0x24, (byte)0x9d, (byte)0x2d, (byte)0x62,
            (byte)0x4a, (byte)0x6c, (byte)0x45, (byte)0x4d, (byte)0x64, (byte)0x44, (byte)0x6d, (byte)0x52, (byte)0x72,
            (byte)0x5c, (byte)0x7c, (byte)0x54, (byte)0x74, (byte)0x5d, (byte)0x7d, (byte)0xa1, (byte)0x1a, (byte)0xac,
            (byte)0x15, (byte)0x1d, (byte)0xa4, (byte)0x14, (byte)0xad, (byte)0x02, (byte)0xb1, (byte)0x0c, (byte)0xbc,
            (byte)0x04, (byte)0xb4, (byte)0x0d, (byte)0xbd, (byte)0xe1, (byte)0xc8, (byte)0xec, (byte)0xc5, (byte)0xcd,
            (byte)0xe4, (byte)0xc4, (byte)0xed, (byte)0xd1, (byte)0xf1, (byte)0xdc, (byte)0xfc, (byte)0xd4, (byte)0xf4,
            (byte)0xdd, (byte)0xfd, (byte)0x36, (byte)0x8e, (byte)0x38, (byte)0x82, (byte)0x8b, (byte)0x30, (byte)0x83,
            (byte)0x39, (byte)0x96, (byte)0x26, (byte)0x9a, (byte)0x28, (byte)0x93, (byte)0x20, (byte)0x9b, (byte)0x29,
            (byte)0x66, (byte)0x4e, (byte)0x68, (byte)0x41, (byte)0x49, (byte)0x60, (byte)0x40, (byte)0x69, (byte)0x56,
            (byte)0x76, (byte)0x58, (byte)0x78, (byte)0x50, (byte)0x70, (byte)0x59, (byte)0x79, (byte)0xa6, (byte)0x1e,
            (byte)0xaa, (byte)0x11, (byte)0x19, (byte)0xa3, (byte)0x10, (byte)0xab, (byte)0x06, (byte)0xb6, (byte)0x08,
            (byte)0xba, (byte)0x00, (byte)0xb3, (byte)0x09, (byte)0xbb, (byte)0xe6, (byte)0xce, (byte)0xea, (byte)0xc2,
            (byte)0xcb, (byte)0xe3, (byte)0xc3, (byte)0xeb, (byte)0xd6, (byte)0xf6, (byte)0xda, (byte)0xfa, (byte)0xd3,
            (byte)0xf3, (byte)0xdb, (byte)0xfb, (byte)0x31, (byte)0x8a, (byte)0x3e, (byte)0x86, (byte)0x8f, (byte)0x37,
            (byte)0x87, (byte)0x3f, (byte)0x92, (byte)0x21, (byte)0x9e, (byte)0x2e, (byte)0x97, (byte)0x27, (byte)0x9f,
            (byte)0x2f, (byte)0x61, (byte)0x48, (byte)0x6e, (byte)0x46, (byte)0x4f, (byte)0x67, (byte)0x47, (byte)0x6f,
            (byte)0x51, (byte)0x71, (byte)0x5e, (byte)0x7e, (byte)0x57, (byte)0x77, (byte)0x5f, (byte)0x7f, (byte)0xa2,
            (byte)0x18, (byte)0xae, (byte)0x16, (byte)0x1f, (byte)0xa7, (byte)0x17, (byte)0xaf, (byte)0x01, (byte)0xb2,
            (byte)0x0e, (byte)0xbe, (byte)0x07, (byte)0xb7, (byte)0x0f, (byte)0xbf, (byte)0xe2, (byte)0xca, (byte)0xee,
            (byte)0xc6, (byte)0xcf, (byte)0xe7, (byte)0xc7, (byte)0xef, (byte)0xd2, (byte)0xf2, (byte)0xde, (byte)0xfe,
            (byte)0xd7, (byte)0xf7, (byte)0xdf, (byte)0xff
        };
    // Tweakey permutation
    private final byte[] TWEAKEY_P = {9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7};

    // round constants
    private final byte[] RC = {
        (byte)0x01, (byte)0x03, (byte)0x07, (byte)0x0F, (byte)0x1F, (byte)0x3E, (byte)0x3D, (byte)0x3B, (byte)0x37, (byte)0x2F,
        (byte)0x1E, (byte)0x3C, (byte)0x39, (byte)0x33, (byte)0x27, (byte)0x0E, (byte)0x1D, (byte)0x3A, (byte)0x35, (byte)0x2B,
        (byte)0x16, (byte)0x2C, (byte)0x18, (byte)0x30, (byte)0x21, (byte)0x02, (byte)0x05, (byte)0x0B, (byte)0x17, (byte)0x2E,
        (byte)0x1C, (byte)0x38, (byte)0x31, (byte)0x23, (byte)0x06, (byte)0x0D, (byte)0x1B, (byte)0x36, (byte)0x2D, (byte)0x1A};

    public RomulusDigest()
    {
        super(ProcessingBufferType.Immediate, 32);
        DigestSize = 32;
        algorithmName = "Romulus Hash";
    }

    void skinny_128_384_plus_enc(byte[] input, byte[] userkey)
    {
        byte[][] state = new byte[4][4];
        byte[][][] keyCells = new byte[3][4][4];
        int i, j, q, r;
        byte pos, tmp;
        byte[][][] keyCells_tmp = new byte[3][4][4];
        for (i = 0; i < 4; ++i)
        {
            q = i << 2;
            System.arraycopy(input, q, state[i], 0, 4);
            System.arraycopy(userkey, q, keyCells[0][i], 0, 4);
            System.arraycopy(userkey, q + 16, keyCells[1][i], 0, 4);
            System.arraycopy(userkey, q + 32, keyCells[2][i], 0, 4);
        }
        for (int round = 0; round < 40; round++)
        {
            //SubCell8;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    state[i][j] = sbox_8[state[i][j] & 0xFF];
                }
            }
            //AddConstants
            state[0][0] ^= (RC[round] & 0xf);
            state[1][0] ^= ((RC[round] >>> 4) & 0x3);
            state[2][0] ^= 0x2;
            //AddKey
            // apply the subtweakey to the internal state
            for (i = 0; i <= 1; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    state[i][j] ^= keyCells[0][i][j] ^ keyCells[1][i][j] ^ keyCells[2][i][j];
                }
            }
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //application of the TWEAKEY permutation
                    pos = TWEAKEY_P[j + (i << 2)];
                    q = pos >>> 2;
                    r = pos & 3;
                    keyCells_tmp[0][i][j] = keyCells[0][q][r];
                    keyCells_tmp[1][i][j] = keyCells[1][q][r];
                    keyCells_tmp[2][i][j] = keyCells[2][q][r];
                }
            }
            // update the subtweakey states with the LFSRs
            for (i = 0; i <= 1; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    //application of LFSRs for TK updates
                    keyCells[0][i][j] = keyCells_tmp[0][i][j];
                    tmp = keyCells_tmp[1][i][j];
                    keyCells[1][i][j] = (byte)(((tmp << 1) & 0xFE) ^ ((tmp >>> 7) & 0x01) ^ ((tmp >>> 5) & 0x01));
                    tmp = keyCells_tmp[2][i][j];
                    keyCells[2][i][j] = (byte)(((tmp >>> 1) & 0x7F) ^ ((tmp << 7) & 0x80) ^ ((tmp << 1) & 0x80));
                }
            }
            for (; i < 4; ++i)
            {
                for (j = 0; j < 4; j++)
                {
                    keyCells[0][i][j] = keyCells_tmp[0][i][j];
                    keyCells[1][i][j] = keyCells_tmp[1][i][j];
                    keyCells[2][i][j] = keyCells_tmp[2][i][j];
                }
            }
            //ShiftRows(state);
            tmp = state[1][3];
            state[1][3] = state[1][2];
            state[1][2] = state[1][1];
            state[1][1] = state[1][0];
            state[1][0] = tmp;
            tmp = state[2][0];
            state[2][0] = state[2][2];
            state[2][2] = tmp;
            tmp = state[2][1];
            state[2][1] = state[2][3];
            state[2][3] = tmp;
            tmp = state[3][0];
            state[3][0] = state[3][1];
            state[3][1] = state[3][2];
            state[3][2] = state[3][3];
            state[3][3] = tmp;
            //MixColumn(state);
            for (j = 0; j < 4; j++)
            {
                state[1][j] ^= state[2][j];
                state[2][j] ^= state[0][j];
                state[3][j] ^= state[2][j];
                tmp = state[3][j];
                state[3][j] = state[2][j];
                state[2][j] = state[1][j];
                state[1][j] = state[0][j];
                state[0][j] = tmp;
            }
        }  //The last subtweakey should not be added
        for (i = 0; i < 16; i++)
        {
            input[i] = (byte)(state[i >>> 2][i & 0x3] & 0xFF);
        }
    }


    // The hirose double-block length (DBL) compression function.
    void hirose_128_128_256(byte[] h, byte[] g, byte[] m, int mOff)
    {
        byte[] key = new byte[48];
        byte[] hh = new byte[16];
        int i;
        // assign the key for the hirose compresison function
        System.arraycopy(g, 0, key, 0, 16);
        System.arraycopy(h, 0, g, 0, 16);
        System.arraycopy(h, 0, hh, 0, 16);
        g[0] ^= 0x01;
        System.arraycopy(m, mOff, key, 16, 32);
        skinny_128_384_plus_enc(h, key);
        skinny_128_384_plus_enc(g, key);
        for (i = 0; i < 16; i++)
        {
            h[i] ^= hh[i];
            g[i] ^= hh[i];
        }
        g[0] ^= 0x01;
    }

    // Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N
    void ipad_256(byte[] m, int inOff, byte[] mp, int len8)
    {
        System.arraycopy(m, inOff, mp, 0, len8);
        Arrays.fill(mp, len8, 31, (byte)0);
        mp[31] = (byte)(len8 & 0x1f);
    }

    @Override
    protected void processBytes(byte[] input, int inOff)
    {
        hirose_128_128_256(h, g, input, inOff);
    }

    @Override
    protected void finish(byte[] output, int outOff)
    {
        byte[] p = new byte[32];
        ipad_256(m_buf, 0, p, m_bufPos);
        h[0] ^= 2;
        hirose_128_128_256(h, g, p, 0);
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
