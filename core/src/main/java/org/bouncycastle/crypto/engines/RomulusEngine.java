package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/**
 * Romulus v1.3, based on the current round 3 submission, https://romulusae.github.io/romulus/
 * Reference C implementation: https://github.com/romulusae/romulus
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
 */

public class RomulusEngine
    implements AEADBlockCipher
{
    public enum RomulusParameters
    {
        RomulusM,
        RomulusN,
        RomulusT,
    }

    private String algorithmName;
    private boolean forEncryption;
    private boolean initialised;
    private final RomulusParameters romulusParameters;
    private int offset;
    private byte[] T;
    private byte[] k;
    private byte[] npub;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private final int CRYPTO_ABYTES = 16;
    private final int AD_BLK_LEN_HALF = 16;

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
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
        0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
        0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
    };

    public RomulusEngine(RomulusParameters romulusParameters)
    {
        this.romulusParameters = romulusParameters;
        switch (romulusParameters)
        {
        case RomulusM:
            algorithmName = "Romulus-M";
            break;
        case RomulusN:
            algorithmName = "Romulus-N";
            break;
        case RomulusT:
            algorithmName = "Romulus-T";
            break;
        }
        initialised = false;
    }

    private void skinny_128_384_plus_enc(byte[] input, byte[] userkey)
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


    // Padding function: pads the byte length of the message mod 16 to the last incomplete block.
// For complete blocks it returns the same block.
    void pad(byte[] m, int mOff, byte[] mp, int l, int len8)
    {
        mp[l - 1] = (byte)(len8 & 0x0f);
        System.arraycopy(m, mOff, mp, 0, len8);
    }

    // G(S): generates the key stream from the internal state by multiplying the state S by the constant matrix G
    void g8A(byte[] s, byte[] c, int cOff)
    {
        int len = Math.min(c.length - cOff, 16);
        for (int i = 0; i < len; i++)
        {
            c[i + cOff] = (byte)(((s[i] & 0xFF) >>> 1) ^ (s[i] & 0x80) ^ ((s[i] & 0x01) << 7));
        }
    }

    // Rho(S,M): pads an M block and outputs S'= M xor S and C = M xor G(S)
    // Inverse-Rho(S,M): pads a C block and outputs S'= C xor G(S) xor S and M = C xor G(S)
    void rho(byte[] m, int mOff, byte[] c, int cOff, byte[] s, int len8)
    {
        byte[] mp = new byte[16];
        pad(m, mOff, mp, AD_BLK_LEN_HALF, len8);
        g8A(s, c, cOff);
        if (forEncryption)
        {
            for (int i = 0; i < AD_BLK_LEN_HALF; i++)
            {
                s[i] ^= mp[i];
                if (i < len8)
                {
                    c[i + cOff] ^= mp[i];
                }
                else
                {
                    c[i + cOff] = 0;
                }
            }
        }
        else
        {
            for (int i = 0; i < AD_BLK_LEN_HALF; i++)
            {
                s[i] ^= mp[i];
                if (i < len8 && i + cOff < c.length)
                {
                    s[i] ^= c[i + cOff];
                    c[i + cOff] ^= mp[i];
                }
            }
        }

    }

    // Applies CNT'=2 * CNT (mod GF(2^56)), where GF(2^56) is defined using the irreducible polynomial
// x^56 + x^7 + x^4 + x^2 + 1
    void lfsr_gf56(byte[] CNT)
    {
        byte fb0 = (byte)((CNT[6] & 0xFF) >>> 7);
        CNT[6] = (byte)(((CNT[6] & 0xFF) << 1) | ((CNT[5] & 0xFF) >>> 7));
        CNT[5] = (byte)(((CNT[5] & 0xFF) << 1) | ((CNT[4] & 0xFF) >>> 7));
        CNT[4] = (byte)((((CNT[4] & 0xFF) << 1) | ((CNT[3] & 0xFF) >>> 7)));
        CNT[3] = (byte)(((CNT[3] & 0xFF) << 1) | ((CNT[2] & 0xFF) >>> 7));
        CNT[2] = (byte)(((CNT[2] & 0xFF) << 1) | ((CNT[1] & 0xFF) >>> 7));
        CNT[1] = (byte)(((CNT[1] & 0xFF) << 1) | ((CNT[0] & 0xFF) >>> 7));
        if (fb0 == 1)
        {
            CNT[0] = (byte)(((CNT[0] & 0xFF) << 1) ^ 0x95);
        }
        else
        {
            CNT[0] = (byte)(((CNT[0] & 0xFF) << 1));
        }
    }

    // An interface between Romulus and the underlying TBC
    void block_cipher(byte[] s, byte[] K, byte[] T, int tOff, byte[] CNT, byte D)
    {
        byte[] KT = new byte[48];
        // Combines the secret key, counter and domain bits to form the full 384-bit tweakey
        System.arraycopy(CNT, 0, KT, 0, 7);
        KT[7] = D;
        Arrays.fill(KT, 8, 16, (byte)0x00);
        System.arraycopy(T, tOff, KT, 16, 16);
        System.arraycopy(K, 0, KT, 32, 16);
        skinny_128_384_plus_enc(s, KT);
    }

    // Calls the TBC using the nonce as part of the tweakey
    void nonce_encryption(byte[] N, byte[] CNT, byte[] s, byte[] k, byte D)
    {
        byte[] T = new byte[16];
        System.arraycopy(N, 0, T, 0, 16);
        block_cipher(s, k, T, 0, CNT, D);
    }

    // Absorbs the AD blocks.
    int ad_encryption(byte[] A, int AOff, byte[] s, byte[] k, int adlen, byte[] CNT, byte D)
    {
        byte[] T = new byte[16];
        byte[] mp = new byte[16];
        int n = 16;
        int i, len8;
        len8 = Math.min(adlen, n);
        adlen -= len8;
        // Rho(S,A) pads an A block and XORs it to the internal state.
        pad(A, AOff, mp, n, len8);
        for (i = 0; i < n; i++)
        {
            s[i] = (byte)(s[i] ^ mp[i]);
        }
        offset = AOff += len8;
        lfsr_gf56(CNT);
        if (adlen != 0)
        {
            len8 = Math.min(adlen, n);
            adlen -= len8;
            pad(A, AOff, T, n, len8);
            offset = AOff + len8;
            block_cipher(s, k, T, 0, CNT, D);
            lfsr_gf56(CNT);
        }
        return adlen;
    }

    private void reset_lfsr_gf56(byte[] CNT)
    {
        CNT[0] = 0x01;
        CNT[1] = 0x00;
        CNT[2] = 0x00;
        CNT[3] = 0x00;
        CNT[4] = 0x00;
        CNT[5] = 0x00;
        CNT[6] = 0x00;
    }

    private void romulus_m_encrypt(byte[] c, byte[] m, int mlen, byte[] ad, int adlen, byte[] N, byte[] k)
    {
        byte[] s = new byte[16];
        byte[] CNT = new byte[7];
        T = new byte[16];
        int xlen, cOff = 0, mOff = 0, adOff = 0, mauth = 0;
        byte w;
        xlen = mlen;
        reset_lfsr_gf56(CNT);
        // Calculating the domain separation bits for the last block MAC TBC call depending on the length of M and AD
        w = 48;
        if ((adlen & 31) == 0 && adlen != 0)
        {
            w ^= 8;
        }
        else if ((adlen & 31) < AD_BLK_LEN_HALF)
        {
            w ^= 2;
        }
        else if ((adlen & 31) != AD_BLK_LEN_HALF)
        {
            w ^= 10;
        }
        if ((xlen & 31) == 0 && xlen != 0)
        {
            w ^= 4;
        }
        else if ((xlen & 31) < AD_BLK_LEN_HALF)
        {
            w ^= 1;
        }
        else if ((xlen & 31) != AD_BLK_LEN_HALF)
        {
            w ^= 5;
        }
        if (forEncryption)
        {
            if (adlen == 0)
            { // AD is an empty string
                lfsr_gf56(CNT);
            }
            else
            {
                while (adlen > 0)
                {
                    offset = adOff;
                    adlen = ad_encryption(ad, adOff, s, k, adlen, CNT, (byte)40);
                    adOff = offset;
                }
            }
            mOff = 0;
            if ((w & 8) == 0)
            {
                byte[] Temp = new byte[16];
                int len8 = Math.min(xlen, AD_BLK_LEN_HALF);
                xlen -= len8;
                pad(m, mOff, Temp, AD_BLK_LEN_HALF, len8);
                block_cipher(s, k, Temp, 0, CNT, (byte)44);
                lfsr_gf56(CNT);
                mOff += len8;
            }
            else if (mlen == 0)
            {
                lfsr_gf56(CNT);
            }
            while (xlen > 0)
            {
                offset = mOff;
                xlen = ad_encryption(m, mOff, s, k, xlen, CNT, (byte)44);
                mOff = offset;
            }
            nonce_encryption(N, CNT, s, k, w);
            // Tag generation
            g8A(s, T, 0);
            mOff -= mlen;
        }
        else
        {
            System.arraycopy(m, mlen, T, 0, CRYPTO_ABYTES);
        }
        reset_lfsr_gf56(CNT);
        System.arraycopy(T, 0, s, 0, AD_BLK_LEN_HALF);
        if (mlen > 0)
        {
            nonce_encryption(N, CNT, s, k, (byte)36);
            while (mlen > AD_BLK_LEN_HALF)
            {
                mlen = mlen - AD_BLK_LEN_HALF;
                rho(m, mOff, c, cOff, s, AD_BLK_LEN_HALF);
                cOff += AD_BLK_LEN_HALF;
                mOff += AD_BLK_LEN_HALF;
                lfsr_gf56(CNT);
                nonce_encryption(N, CNT, s, k, (byte)36);
            }
            rho(m, mOff, c, cOff, s, mlen);
        }
        if (!forEncryption)
        {
            Arrays.fill(s, (byte)0);
            reset_lfsr_gf56(CNT);
            if (adlen == 0)
            { // AD is an empty string
                lfsr_gf56(CNT);
            }
            else
            {
                while (adlen > 0)
                {
                    offset = adOff;
                    adlen = ad_encryption(ad, adOff, s, k, adlen, CNT, (byte)40);
                    adOff = offset;
                }
            }
            if ((w & 8) == 0)
            {
                byte[] Temp = new byte[16];
                int len8 = Math.min(xlen, AD_BLK_LEN_HALF);
                xlen -= len8;
                pad(c, mauth, Temp, AD_BLK_LEN_HALF, len8);
                block_cipher(s, k, Temp, 0, CNT, (byte)44);
                lfsr_gf56(CNT);
                mauth += len8;
                mOff += len8;
            }
            else if (mlen == 0)
            {
                lfsr_gf56(CNT);
            }
            while (xlen > 0)
            {
                offset = mauth;
                xlen = ad_encryption(c, mauth, s, k, xlen, CNT, (byte)44);
                mauth = offset;
            }
            nonce_encryption(N, CNT, s, k, w);
            // Tag generation
            g8A(s, T, 0);
        }
    }

    private void romulus_n(byte[] c, byte[] I, int mlen, byte[] A, int adlen, byte[] N, byte[] k)
    {
        byte[] s = new byte[16];
        byte[] CNT = new byte[7];
        int mOff = 0, cOff = 0;
        reset_lfsr_gf56(CNT);
        if (adlen == 0)
        { // AD is an empty string
            lfsr_gf56(CNT);
            nonce_encryption(N, CNT, s, k, (byte)0x1a);
        }
        else
        {
            while (adlen > 0)
            {
                if (adlen < AD_BLK_LEN_HALF)
                { // The last block of AD is odd and incomplete
                    adlen = ad_encryption(A, 0, s, k, adlen, CNT, (byte)0x08);
                    nonce_encryption(N, CNT, s, k, (byte)0x1a);
                }
                else if (adlen == AD_BLK_LEN_HALF)
                { // The last block of AD is odd and complete
                    adlen = ad_encryption(A, 0, s, k, adlen, CNT, (byte)0x08);
                    nonce_encryption(N, CNT, s, k, (byte)0x18);
                }
                else if (adlen < (AD_BLK_LEN_HALF + AD_BLK_LEN_HALF))
                { // The last block of AD is even and incomplete
                    adlen = ad_encryption(A, 0, s, k, adlen, CNT, (byte)0x08);
                    nonce_encryption(N, CNT, s, k, (byte)0x1a);
                }
                else if (adlen == (AD_BLK_LEN_HALF + AD_BLK_LEN_HALF))
                { // The last block of AD is even and complete
                    adlen = ad_encryption(A, 0, s, k, adlen, CNT, (byte)0x08);
                    nonce_encryption(N, CNT, s, k, (byte)0x18);
                }
                else
                { // A normal full pair of blocks of AD
                    adlen = ad_encryption(A, 0, s, k, adlen, CNT, (byte)0x08);
                }
            }
        }
        reset_lfsr_gf56(CNT);
        if (mlen == 0)
        { // M is an empty string
            lfsr_gf56(CNT);
            nonce_encryption(N, CNT, s, k, (byte)0x15);
        }
        else
        {
            int tmp;
            while (mlen > 0)
            {
                if (mlen < AD_BLK_LEN_HALF)
                { // The last block of M is incomplete
                    tmp = mlen;
                    mlen = msg_encryption(I, mOff, c, cOff, N, CNT, s, k, (byte)0x15, mlen);
                }
                else if (mlen == AD_BLK_LEN_HALF)
                { // The last block of M is complete
                    tmp = AD_BLK_LEN_HALF;
                    mlen = msg_encryption(I, mOff, c, cOff, N, CNT, s, k, (byte)0x14, mlen);
                }
                else
                { // A normal full message block
                    tmp = AD_BLK_LEN_HALF;
                    mlen = msg_encryption(I, mOff, c, cOff, N, CNT, s, k, (byte)0x04, mlen);
                }
                mOff += tmp;
                cOff += tmp;
            }
        }
        // Tag generation
        T = new byte[16];
        g8A(s, T, 0);
    }

    // Absorbs and encrypts the message blocks.
    int msg_encryption(byte[] m, int mOff, byte[] c, int cOff, byte[] N, byte[] CNT, byte[] s, byte[] k, byte D, int mlen)
    {
        int len8 = Math.min(mlen, AD_BLK_LEN_HALF);
        mlen -= len8;
        rho(m, mOff, c, cOff, s, len8);
        lfsr_gf56(CNT);
        nonce_encryption(N, CNT, s, k, D);
        return mlen;
    }

    private void romulus_t_encrypt(byte[] c, byte[] m, int mlen, byte[] A, int adlen, byte[] N, byte[] k)
        throws InvalidCipherTextException
    {
        byte[] Z = new byte[16];
        byte[] CNT = new byte[7];
        byte[] CNT_Z = new byte[7];
        int mlen_int;
        byte[] LR = new byte[32];
        int i;
        int mOff = 0, cOff = 0;
        reset_lfsr_gf56(CNT);
        // Initialization function: KDF
        byte[] S = new byte[16];
        mlen_int = mlen;
        if (!forEncryption)
        {
            // T = hash(ipad*(A)||ipad*(C)||N||CNT)
            T = new byte[16];
            crypto_hash_vector(LR, A, adlen, m, mOff, mlen_int, N, CNT);
            // Generates the tag T from the final state S by applying the Tag Generation Function (TGF).
            block_cipher(LR, k, LR, 16, CNT_Z, (byte)68);
            System.arraycopy(LR, 0, T, 0, 16);
            reset_lfsr_gf56(CNT);
            tagVerification(m, mlen_int);
        }
        T = new byte[16];
        System.arraycopy(N, 0, Z, 0, 16);
        block_cipher(Z, k, T, 0, CNT_Z, (byte)66);
        while (mlen != 0)
        {
            int len8 = Math.min(mlen, 16);
            mlen -= len8;
            System.arraycopy(N, 0, S, 0, 16);
            block_cipher(S, Z, T, 0, CNT, (byte)64);
            for (i = 0; i < len8 && i + cOff < c.length; i++)
            {
                c[i + cOff] = (byte)((m[i + mOff]) ^ S[i]);
            }
            cOff += len8;
            mOff += len8;
            System.arraycopy(N, 0, S, 0, 16);
            if (mlen != 0)
            {
                block_cipher(S, Z, T, 0, CNT, (byte)65);
                System.arraycopy(S, 0, Z, 0, 16);
            }
            lfsr_gf56(CNT);
        }
        if (forEncryption)
        {
            // T = hash(A||N||M)
            // We need to first pad A, N and C
            cOff -= mlen_int;
            crypto_hash_vector(LR, A, adlen, c, cOff, mlen_int, N, CNT);
            // Generates the tag T from the final state S by applying the Tag Generation Function (TGF).
            block_cipher(LR, k, LR, 16, CNT_Z, (byte)68);
            System.arraycopy(LR, 0, T, 0, 16);
        }
    }

    // This function is required for Romulus-T. It assumes that the input comes in three parts that can
// be stored in different locations in the memory. It processes these inputs sequentially.
// The padding is ipad_256(ipad*_128(A)||ipad*_128(C)||N|| CNT )
// A and C are of variable length, while N is of 16 bytes and CNT is of 7 bytes
    private void crypto_hash_vector(byte[] out, byte[] A, int adlen, byte[] C, int cOff, int clen, byte[] N, byte[] CNT)
    {
        byte[] h = new byte[16];
        byte[] g = new byte[16];
        byte[] p = new byte[32];
        int aOff = 0;
        int n = 16;
        byte adempty = (byte)((adlen == 0) ? 1 : 0);
        byte cempty = (byte)(clen == 0 ? 1 : 0);
        reset_lfsr_gf56(CNT);
        while (adlen >= 32)
        { // AD Normal loop
            hirose_128_128_256(h, g, A, aOff);
            aOff += 32;
            adlen -= 32;
        }
        // Partial block (or in case there is no partial block we add a 0^2n block
        if (adlen >= 16)
        {
            ipad_128(A, aOff, p, 0, 32, adlen);
            hirose_128_128_256(h, g, p, 0);
        }
        else if ((adlen >= 0) && (adempty == 0))
        {
            ipad_128(A, aOff, p, 0, 16, adlen);
            if (clen >= 16)
            {
                System.arraycopy(C, cOff, p, 16, 16);
                hirose_128_128_256(h, g, p, 0);
                lfsr_gf56(CNT);
                clen -= 16;
                cOff += 16;
            }
            else if (clen > 0)
            {
                ipad_128(C, cOff, p, 16, 16, clen);
                hirose_128_128_256(h, g, p, 0);
                clen = 0;
                cempty = 1;
                cOff += 16;
                lfsr_gf56(CNT);
            }
            else
            {
                System.arraycopy(N, 0, p, 16, 16);
                hirose_128_128_256(h, g, p, 0);
                n = 0;
            }
        }
        while (clen >= 32)
        { // C Normal loop
            hirose_128_128_256(h, g, C, cOff);
            cOff += 32;
            clen -= 32;
            lfsr_gf56(CNT);
            lfsr_gf56(CNT);
        }
        if (clen > 16)
        {
            ipad_128(C, cOff, p, 0, 32, clen);
            hirose_128_128_256(h, g, p, 0);
            lfsr_gf56(CNT);
            lfsr_gf56(CNT);
        }
        else if (clen == 16)
        {
            ipad_128(C, cOff, p, 0, 32, clen);
            hirose_128_128_256(h, g, p, 0);
            lfsr_gf56(CNT);
        }
        else if ((clen >= 0) && (cempty == 0))
        {
            ipad_128(C, cOff, p, 0, 16, clen);
            if (clen > 0)
            {
                lfsr_gf56(CNT);
            }
            // Pad the nonce
            System.arraycopy(N, 0, p, 16, 16);
            hirose_128_128_256(h, g, p, 0);
            n = 0;
        }
        if (n == 16)
        {
            // Pad the nonce and counter
            System.arraycopy(N, 0, p, 0, 16);
            System.arraycopy(CNT, 0, p, 16, 7);
            ipad_256(p, p, 23);
        }
        else
        {
            ipad_256(CNT, p, 7);
        }
        h[0] ^= 2;
        hirose_128_128_256(h, g, p, 0);
        // Assign the output tag
        System.arraycopy(h, 0, out, 0, 16);
        System.arraycopy(g, 0, out, 16, 16);
    }

    // Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N
    void ipad_256(byte[] m, byte[] mp, int len8)
    {
        System.arraycopy(m, 0, mp, 0, len8);
        Arrays.fill(mp, len8, 31, (byte)0);
        mp[31] = (byte)(len8 & 0x1f);
    }

    // Padding function: pads the byte length of the message mod 32 to the last incomplete block.
// For complete blocks it returns the same block. For an empty block it returns a 0^2n string.
// The function is called for full block messages to add a 0^2n block. This and the modulus are
// the only differences compared to the use in Romulus-N
    void ipad_128(byte[] m, int mOff, byte[] mp, int mpOff, int l, int len8)
    {
        System.arraycopy(m, mOff, mp, mpOff, len8);
        Arrays.fill(mp, len8 + mpOff, l - 1 + mpOff, (byte)0);
        mp[mpOff + l - 1] = (byte)(len8 & 0xf);
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

    @Override
    public BlockCipher getUnderlyingCipher()
    {
        return null;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException("Romulus init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV)params;
        npub = ivParams.getIV();
        if (npub == null || npub.length != CRYPTO_ABYTES)
        {
            throw new IllegalArgumentException("Romulus requires exactly " + CRYPTO_ABYTES + " bytes of IV");
        }

        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException("Romulus init parameters must include a key");
        }

        KeyParameter key = (KeyParameter)ivParams.getParameters();
        k = key.getKey();
        if (k.length != 16)
        {
            throw new IllegalArgumentException("Romulus key must be 16 bytes long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        initialised = true;
        reset(false);
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    @Override
    public void processAADByte(byte in)
    {
        aadData.write(in);
    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        if (inOff + len > in.length)
        {
            throw new DataLengthException(algorithmName + " input buffer too short");
        }
        aadData.write(in, inOff, len);
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        message.write(in);
        return 0;
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException(algorithmName + " input buffer too short");
        }
        message.write(input, inOff, len);
        return 0;
    }

    @Override
    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException(algorithmName + " needs call init function before dofinal");
        }
        int len = message.size(), inOff = 0;
        if ((forEncryption && len + CRYPTO_ABYTES + outOff > out.length) ||
            (!forEncryption && len - CRYPTO_ABYTES + outOff > out.length))
        {
            throw new OutputLengthException("output buffer is too short");
        }
        byte[] ad = aadData.toByteArray();
        int adlen = ad.length;
        byte[] input = message.toByteArray();

        if ((ad.length & 7) != 0)
        {
            byte[] tmp = new byte[((ad.length >> 3) << 3) + 16];
            System.arraycopy(ad, 0, tmp, 0, adlen);
            ad = tmp;
        }
        if ((len & 7) != 0)
        {
            byte[] tmp = new byte[((len >> 3) << 3) + 16];
            System.arraycopy(input, inOff, tmp, 0, len);
            input = tmp;
        }
        byte[] out_tmp = new byte[((len >> 3) << 3) + 16];
        len -= (forEncryption ? 0 : 16);
        switch (romulusParameters)
        {
        case RomulusM:
            romulus_m_encrypt(out_tmp, input, len, ad, adlen, npub, k);
            break;
        case RomulusN:
            romulus_n(out_tmp, input, len, ad, adlen, npub, k);
            break;
        case RomulusT:
            romulus_t_encrypt(out_tmp, input, len, ad, adlen, npub, k);
            break;
        }
        System.arraycopy(out_tmp, 0, out, outOff, len);
        outOff += len;
        if (forEncryption)
        {
            System.arraycopy(T, 0, out, outOff, CRYPTO_ABYTES);
            len += CRYPTO_ABYTES;
        }
        else
        {
            if (romulusParameters != RomulusParameters.RomulusT)
            {
                tagVerification(input, len);
            }
        }
        reset(false);
        return len;
    }

    private void tagVerification(byte[] input, int inOff)
        throws InvalidCipherTextException
    {
        for (int i = 0; i < 16; ++i)
        {
            if (T[i] != input[inOff + i])
            {
                throw new InvalidCipherTextException("mac check in " + algorithmName + " failed");
            }
        }
    }

    @Override
    public byte[] getMac()
    {
        return T;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        int totalData = message.size() + len;
        if (!forEncryption)
        {
            if (totalData < 32)
            {
                return 0;
            }
            totalData -= CRYPTO_ABYTES;
        }
        return totalData - totalData % CRYPTO_ABYTES;
    }

    @Override
    public int getOutputSize(int len)
    {
        int totalData = message.size() + len;
        if (forEncryption)
        {
            return totalData + CRYPTO_ABYTES;
        }
        return Math.max(0, totalData - CRYPTO_ABYTES);
    }

    @Override
    public void reset()
    {
        reset(true);
    }

    private void reset(boolean clearMac)
    {
        if (clearMac)
        {
            T = null;
        }
        aadData.reset();
        message.reset();
    }

    public int getKeyBytesSize()
    {
        return 16;
    }

    public int getIVBytesSize()
    {
        return 16;
    }

    public int getBlockSize()
    {
        return 32;
    }
}
