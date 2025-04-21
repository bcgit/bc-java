package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.digests.RomulusDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/**
 * Romulus v1.3, based on the current round 3 submission, https://romulusae.github.io/romulus/
 * Reference C implementation: https://github.com/romulusae/romulus
 * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
 */

public class RomulusEngine
    extends AEADBaseEngine
{
    public static class RomulusParameters
    {
        public static final int ROMULUS_M = 0;
        public static final int ROMULUS_N = 1;
        public static final int ROMULUS_T = 2;

        public static final RomulusParameters RomulusM = new RomulusParameters(ROMULUS_M);
        public static final RomulusParameters RomulusN = new RomulusParameters(ROMULUS_N);
        public static final RomulusParameters RomulusT = new RomulusParameters(ROMULUS_T);

        private final int ord;

        RomulusParameters(int ord)
        {
            this.ord = ord;
        }
    }

    private byte[] k;
    private byte[] npub;
    private static final int AD_BLK_LEN_HALF = 16;
    private Instance instance;
    private final byte[] CNT;

    // Packing of data is done as follows (state[i][j] stands for row i and column j):
    // 0  1  2  3
    // 4  5  6  7
    // 8  9 10 11
    //12 13 14 15

    // 8-bit Sbox
    private static final byte[] sbox_8 =
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
    private static final byte[] TWEAKEY_P = {9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7};

    // round constants
    private static final byte[] RC = {
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
        0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
        0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
    };

    public RomulusEngine(RomulusParameters romulusParameters)
    {
        KEY_SIZE = IV_SIZE = MAC_SIZE = BlockSize = AADBufferSize = 16;
        CNT = new byte[7];
        switch (romulusParameters.ord)
        {
        case RomulusParameters.ROMULUS_M:
            algorithmName = "Romulus-M";
            instance = new RomulusM();
            break;
        case RomulusParameters.ROMULUS_N:
            algorithmName = "Romulus-N";
            instance = new RomulusN();
            break;
        case RomulusParameters.ROMULUS_T:
            algorithmName = "Romulus-T";
            AADBufferSize = 32;
            instance = new RomulusT();
            break;
        }
        setInnerMembers(romulusParameters == RomulusParameters.RomulusN ? ProcessingBufferType.Buffered : ProcessingBufferType.Immediate,
            AADOperatorType.Counter,
            romulusParameters == RomulusParameters.RomulusM ? DataOperatorType.Stream : DataOperatorType.Counter);
    }

    private interface Instance
    {
        void processFinalBlock(byte[] output, int outOff);

        void processBufferAAD(byte[] input, int inOff);

        void processFinalAAD();

        void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff);

        void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff);

        void reset();
    }

    private class RomulusM
        implements Instance
    {
        private final byte[] mac_s = new byte[16];
        private final byte[] mac_CNT = new byte[7];
        private final byte[] s = new byte[16];
        private int offset;
        private boolean twist = true;

        public RomulusM()
        {
        }

        @Override
        public void processFinalBlock(byte[] output, int outOff)
        {
            byte w = 48;
            int adlen = aadOperator.getLen();
            int mlen = dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE);
            byte[] m = ((StreamDataOperator)dataOperator).getBytes();
            int xlen, mOff = 0, mauth = outOff;
            xlen = mlen;
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
            if ((mlen & 31) == 0 && mlen != 0)
            {
                w ^= 4;
            }
            else if ((mlen & 31) < AD_BLK_LEN_HALF)
            {
                w ^= 1;
            }
            else if ((mlen & 31) != AD_BLK_LEN_HALF)
            {
                w ^= 5;
            }
            if (forEncryption)
            {
                if ((w & 8) == 0)
                {
                    byte[] Temp = new byte[16];
                    int len8 = Math.min(xlen, AD_BLK_LEN_HALF);
                    xlen -= len8;
                    pad(m, mOff, Temp, AD_BLK_LEN_HALF, len8);
                    block_cipher(mac_s, k, Temp, 0, mac_CNT, (byte)44);
                    lfsr_gf56(mac_CNT);
                    mOff += len8;
                }
                else if (mlen == 0)
                {
                    lfsr_gf56(mac_CNT);
                }
                while (xlen > 0)
                {
                    offset = mOff;
                    xlen = ad_encryption(m, mOff, mac_s, k, xlen, mac_CNT);
                    mOff = offset;
                }
                block_cipher(mac_s, k, npub, 0, mac_CNT, w);
                // Tag generation
                g8A(mac_s, mac, 0);
                mOff -= mlen;
            }
            else
            {
                System.arraycopy(m, mlen, mac, 0, MAC_SIZE);
            }
            reset_lfsr_gf56(CNT);
            System.arraycopy(mac, 0, s, 0, AD_BLK_LEN_HALF);
            if (mlen > 0)
            {
                block_cipher(s, k, npub, 0, CNT, (byte)36);
                while (mlen > AD_BLK_LEN_HALF)
                {
                    mlen = mlen - AD_BLK_LEN_HALF;
                    rho(m, mOff, output, outOff, s, AD_BLK_LEN_HALF);
                    outOff += AD_BLK_LEN_HALF;
                    mOff += AD_BLK_LEN_HALF;
                    lfsr_gf56(CNT);
                    block_cipher(s, k, npub, 0, CNT, (byte)36);
                }
                rho(m, mOff, output, outOff, s, mlen);
            }
            if (!forEncryption)
            {
                if ((w & 8) == 0)
                {
                    byte[] Temp = new byte[16];
                    int len8 = Math.min(xlen, AD_BLK_LEN_HALF);
                    xlen -= len8;
                    pad(output, mauth, Temp, AD_BLK_LEN_HALF, len8);
                    block_cipher(mac_s, k, Temp, 0, mac_CNT, (byte)44);
                    lfsr_gf56(mac_CNT);
                    mauth += len8;
                }
                else if (mlen == 0)
                {
                    lfsr_gf56(mac_CNT);
                }
                while (xlen > 0)
                {
                    offset = mauth;
                    xlen = ad_encryption(output, mauth, mac_s, k, xlen, mac_CNT);
                    mauth = offset;
                }
                block_cipher(mac_s, k, npub, 0, mac_CNT, w);
                // Tag generation
                g8A(mac_s, mac, 0);
                System.arraycopy(m, dataOperator.getLen() - MAC_SIZE, m_buf, 0, MAC_SIZE);
                m_bufPos = 0;
            }
        }

        int ad_encryption(byte[] A, int AOff, byte[] s, byte[] k, int adlen, byte[] CNT)
        {
            byte[] T = new byte[16];
            byte[] mp = new byte[16];
            int n = 16;
            int len8;
            len8 = Math.min(adlen, n);
            adlen -= len8;
            // Rho(S,A) pads an A block and XORs it to the internal state.
            pad(A, AOff, mp, n, len8);
            Bytes.xorTo(n, mp, s);
            offset = AOff += len8;
            lfsr_gf56(CNT);
            if (adlen != 0)
            {
                len8 = Math.min(adlen, n);
                adlen -= len8;
                pad(A, AOff, T, n, len8);
                offset = AOff + len8;
                block_cipher(s, k, T, 0, CNT, (byte)44);
                lfsr_gf56(CNT);
            }
            return adlen;
        }

        @Override
        public void processBufferAAD(byte[] input, int inOff)
        {
            if (twist)
            {
                Bytes.xorTo(MAC_SIZE, input, inOff, mac_s);
            }
            else
            {
                block_cipher(mac_s, k, input, inOff, mac_CNT, (byte)40);
            }
            twist = !twist;
            lfsr_gf56(mac_CNT);
        }

        @Override
        public void processFinalAAD()
        {
            if (aadOperator.getLen() == 0)
            {
                // AD is an empty string
                lfsr_gf56(mac_CNT);
            }
            else if (m_aadPos != 0)
            {
                Arrays.fill(m_aad, m_aadPos, BlockSize - 1, (byte)0);
                m_aad[BlockSize - 1] = (byte)(m_aadPos & 0x0f);
                if (twist)
                {
                    Bytes.xorTo(BlockSize, m_aad, mac_s);
                }
                else
                {
                    block_cipher(mac_s, k, m_aad, 0, mac_CNT, (byte)40);
                }
                lfsr_gf56(mac_CNT);
            }
            m_aadPos = 0;
            m_bufPos = dataOperator.getLen();
        }

        @Override
        public void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
        {
        }

        @Override
        public void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
        {
        }

        @Override
        public void reset()
        {
            Arrays.clear(s);
            Arrays.clear(mac_s);
            reset_lfsr_gf56(mac_CNT);
            reset_lfsr_gf56(CNT);
            twist = true;
        }
    }

    private class RomulusN
        implements Instance
    {
        private final byte[] s;
        boolean twist;

        public RomulusN()
        {
            s = new byte[AD_BLK_LEN_HALF];
        }

        @Override
        public void processFinalBlock(byte[] output, int outOff)
        {
            int messegeLen = dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE);
            if (messegeLen == 0)
            {
                lfsr_gf56(CNT);
                block_cipher(s, k, npub, 0, CNT, (byte)0x15);
            }
            else if (m_bufPos != 0)
            {
                int len8 = Math.min(m_bufPos, AD_BLK_LEN_HALF);
                rho(m_buf, 0, output, outOff, s, len8);
                lfsr_gf56(CNT);
                block_cipher(s, k, npub, 0, CNT, m_bufPos == AD_BLK_LEN_HALF ? (byte)0x14 : (byte)0x15);
            }
            g8A(s, mac, 0);
        }

        @Override
        public void processBufferAAD(byte[] input, int inOff)
        {
            if (twist)
            {
                Bytes.xorTo(AD_BLK_LEN_HALF, input, inOff, s);
            }
            else
            {
                block_cipher(s, k, input, inOff, CNT, (byte)0x08);
            }
            lfsr_gf56(CNT);
            twist = !twist;
        }

        @Override
        public void processFinalAAD()
        {
            if (m_aadPos != 0)
            {
                byte[] mp = new byte[AD_BLK_LEN_HALF];
                int len8 = Math.min(m_aadPos, AD_BLK_LEN_HALF);
                pad(m_aad, 0, mp, AD_BLK_LEN_HALF, len8);
                if (twist)
                {
                    Bytes.xorTo(AD_BLK_LEN_HALF, mp, s);
                }
                else
                {
                    block_cipher(s, k, mp, 0, CNT, (byte)0x08);
                }
                lfsr_gf56(CNT);
            }
            if (aadOperator.getLen() == 0)
            {
                lfsr_gf56(CNT);
                block_cipher(s, k, npub, 0, CNT, (byte)0x1a);
            }
            else if ((m_aadPos & 15) != 0)
            {
                block_cipher(s, k, npub, 0, CNT, (byte)0x1a);
            }
            else
            {
                block_cipher(s, k, npub, 0, CNT, (byte)0x18);
            }
            reset_lfsr_gf56(CNT);
        }

        @Override
        public void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
        {
            g8A(s, output, outOff);
            for (int i = 0; i < AD_BLK_LEN_HALF; i++)
            {
                s[i] ^= input[i + inOff];
                output[i + outOff] ^= input[i + inOff];
            }
            lfsr_gf56(CNT);
            block_cipher(s, k, npub, 0, CNT, (byte)0x04);
        }

        @Override
        public void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
        {
            g8A(s, output, outOff);
            for (int i = 0; i < AD_BLK_LEN_HALF; i++)
            {
                output[i + outOff] ^= input[i + inOff];
                s[i] ^= output[i + outOff];
            }
            lfsr_gf56(CNT);
            block_cipher(s, k, npub, 0, CNT, (byte)0x04);
        }

        @Override
        public void reset()
        {
            Arrays.clear(s);
            reset_lfsr_gf56(CNT);
            twist = true;
        }
    }

    private class RomulusT
        implements Instance
    {
        private final byte[] h = new byte[16];
        private final byte[] g = new byte[16];
        byte[] Z = new byte[16];
        byte[] CNT_Z = new byte[7];
        byte[] LR = new byte[32];
        byte[] T = new byte[16];
        // Initialization function: KDF
        byte[] S = new byte[16];

        @Override
        public void processFinalBlock(byte[] output, int outOff)
        {
            int n = 16;
            int messegeLen = dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE);
            if (m_bufPos != 0)
            {
                int len8 = Math.min(m_bufPos, 16);
                System.arraycopy(npub, 0, S, 0, 16);
                block_cipher(S, Z, T, 0, CNT, (byte)64);
                Bytes.xor(len8, m_buf, S, output, outOff);
                System.arraycopy(npub, 0, S, 0, 16);

                lfsr_gf56(CNT);

                byte[] macIn;
                int macInOff;
                if (forEncryption)
                {
                    macIn = output;
                    macInOff = outOff;
                }
                else
                {
                    macIn = m_buf;
                    macInOff = 0;
                }
                System.arraycopy(macIn, macInOff, m_aad, m_aadPos, m_bufPos);
                Arrays.fill(m_aad, m_aadPos + m_bufPos, AADBufferSize - 1, (byte)0);
                m_aad[m_aadPos + BlockSize - 1] = (byte)(m_bufPos & 0xf);
                if (m_aadPos == 0)
                {
                    System.arraycopy(npub, 0, m_aad, BlockSize, BlockSize);
                    n = 0;
                }
                hirose_128_128_256(h, g, m_aad, 0);
                lfsr_gf56(CNT_Z);
            }
            else if (m_aadPos != 0)
            {
                if (messegeLen > 0)
                {
                    Arrays.fill(m_aad, BlockSize, AADBufferSize, (byte)0);
                }
                else if (aadOperator.getLen() != 0)
                {
                    System.arraycopy(npub, 0, m_aad, m_aadPos, 16);
                    n = 0;
                    m_aadPos = 0;
                }
                hirose_128_128_256(h, g, m_aad, 0);
            }
            else if (messegeLen > 0)
            {
                Arrays.fill(m_aad, 0, BlockSize, (byte)0);
                System.arraycopy(npub, 0, m_aad, BlockSize, BlockSize);
                n = 0;
                hirose_128_128_256(h, g, m_aad, 0);
            }

            if (n == 16)
            {
                // Pad the nonce and counter
                System.arraycopy(npub, 0, m_aad, 0, 16);
                System.arraycopy(CNT, 0, m_aad, 16, 7);
                Arrays.fill(m_aad, 23, 31, (byte)0);
                m_aad[31] = (byte)(23 & 0x1f);
            }
            else
            {
                System.arraycopy(CNT_Z, 0, m_aad, 0, 7);
                Arrays.fill(m_aad, 7, 31, (byte)0);
                m_aad[31] = (byte)(7 & 0x1f);
            }
            h[0] ^= 2;
            hirose_128_128_256(h, g, m_aad, 0);
            // Assign the output tag
            System.arraycopy(h, 0, LR, 0, 16);
            System.arraycopy(g, 0, LR, 16, 16);
            Arrays.clear(CNT_Z);
            block_cipher(LR, k, LR, 16, CNT_Z, (byte)68);
            System.arraycopy(LR, 0, mac, 0, MAC_SIZE);
        }

        @Override
        public void processBufferAAD(byte[] input, int inOff)
        {
            hirose_128_128_256(h, g, input, inOff);
        }

        @Override
        public void processFinalAAD()
        {
            // Partial block (or in case there is no partial block we add a 0^2n block
            Arrays.fill(m_aad, m_aadPos, AADBufferSize - 1, (byte)0);
            if (m_aadPos >= 16)
            {
                m_aad[AADBufferSize - 1] = (byte)(m_aadPos & 0xf);
                hirose_128_128_256(h, g, m_aad, 0);
                m_aadPos = 0;
            }
            else if ((m_aadPos >= 0) && (aadOperator.getLen() != 0))
            {
                m_aad[BlockSize - 1] = (byte)(m_aadPos & 0xf);
                m_aadPos = BlockSize;
            }
        }

        private void processBuffer(byte[] input, int inOff, byte[] output, int outOff)
        {
            System.arraycopy(npub, 0, S, 0, 16);
            block_cipher(S, Z, T, 0, CNT, (byte)64);
            Bytes.xor(AD_BLK_LEN_HALF, S, input, inOff, output, outOff);
            System.arraycopy(npub, 0, S, 0, 16);
            block_cipher(S, Z, T, 0, CNT, (byte)65);
            System.arraycopy(S, 0, Z, 0, 16);
            lfsr_gf56(CNT);
        }

        private void processAfterAbsorbCiphertext()
        {
            if (m_aadPos == BlockSize)
            {
                hirose_128_128_256(h, g, m_aad, 0);
                m_aadPos = 0;
            }
            else
            {
                m_aadPos = BlockSize;
            }
            lfsr_gf56(CNT_Z);
        }

        @Override
        public void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
        {
            processBuffer(input, inOff, output, outOff);
            // ipad_256(ipad*_128(A)||ipad*_128(C)||N|| CNT
            System.arraycopy(output, outOff, m_aad, m_aadPos, BlockSize);
            processAfterAbsorbCiphertext();
        }

        @Override
        public void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
        {
            processBuffer(input, inOff, output, outOff);
            // ipad_256(ipad*_128(A)||ipad*_128(C)||N|| CNT
            System.arraycopy(input, inOff, m_aad, m_aadPos, BlockSize);
            processAfterAbsorbCiphertext();
        }

        @Override
        public void reset()
        {
            Arrays.clear(h);
            Arrays.clear(g);
            Arrays.clear(LR);
            Arrays.clear(T);
            Arrays.clear(S);
            Arrays.clear(CNT_Z);
            reset_lfsr_gf56(CNT);
            System.arraycopy(npub, 0, Z, 0, IV_SIZE);
            block_cipher(Z, k, T, 0, CNT_Z, (byte)66);
            reset_lfsr_gf56(CNT_Z);
        }
    }

    private static void skinny_128_384_plus_enc(byte[] input, byte[] userkey)
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
        System.arraycopy(T, tOff, KT, 16, 16);
        System.arraycopy(K, 0, KT, 32, 16);
        skinny_128_384_plus_enc(s, KT);
    }

    private void reset_lfsr_gf56(byte[] CNT)
    {
        CNT[0] = 0x01;
        Arrays.fill(CNT, 1, 7, (byte)0);
    }

    public static void hirose_128_128_256(RomulusDigest.Friend friend, byte[] h, byte[] g, byte[] m, int mOff)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by RomulusDigest");
        }
        hirose_128_128_256(h, g, m, mOff);
    }

    // The hirose double-block length (DBL) compression function.
    static void hirose_128_128_256(byte[] h, byte[] g, byte[] m, int mOff)
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
    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        npub = iv;
        k = key;
    }

    protected void finishAAD(State nextState, boolean isDoFinal)
    {
        // State indicates whether we ever received AAD
        finishAAD1(nextState);
    }

    protected void processBufferAAD(byte[] input, int inOff)
    {
        instance.processBufferAAD(input, inOff);
    }

    protected void processFinalAAD()
    {
        instance.processFinalAAD();
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        instance.processFinalBlock(output, outOff);
    }

    @Override
    protected void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        instance.processBufferEncrypt(input, inOff, output, outOff);
    }

    @Override
    protected void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        instance.processBufferDecrypt(input, inOff, output, outOff);
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        instance.reset();
    }
}
