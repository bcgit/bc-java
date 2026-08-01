package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.digests.PhotonBeetleDigest;
import org.bouncycastle.util.Bytes;

/**
 * Photon-Beetle, <a href="https://www.isical.ac.in/~lightweight/beetle/"></a>
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
 * <p>
 * Photon-Beetle with reference to C Reference Impl from: https://github.com/PHOTON-Beetle/Software
 * </p>
 */

public class PhotonBeetleEngine
    extends AEADBaseEngine
{
    public enum PhotonBeetleParameters
    {
        pb32,
        pb128
    }

    private boolean input_empty;
    private byte[] K;
    private byte[] N;
    private byte[] state;
    private final int RATE_INBYTES_HALF;
    private final int STATE_INBYTES;
    private final int LAST_THREE_BITS_OFFSET;
    private static final int D = 8;
    private static final byte[][] RC = {
        {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
        {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
        {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
        {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
        {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
        {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
        {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
        {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
    };
    private static final byte[][] MixColMatrix = {
        {2, 4, 2, 11, 2, 8, 5, 6},
        {12, 9, 8, 13, 7, 7, 5, 2},
        {4, 4, 13, 13, 9, 4, 13, 9},
        {1, 6, 5, 1, 12, 13, 15, 14},
        {15, 12, 9, 13, 14, 5, 14, 13},
        {9, 14, 5, 15, 4, 12, 9, 6},
        {12, 2, 2, 10, 3, 1, 1, 14},
        {15, 1, 13, 10, 5, 10, 2, 3}
    };

    private static final byte[] sbox = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

    // Precomputed GF(2^4) multiplication table (with the field reduction folded in), indexed
    // [(x << 4) | y] = x (x) y. The MixColumn step multiplies fixed matrix nibbles by state
    // nibbles; the reference recomputed each product via bit-decomposition + a two-step reduction
    // (32 ops per entry, 64 entries x 12 rounds). One table lookup replaces that. Byte-identical:
    // field reduction is linear over XOR, so XOR-ing reduced products equals reducing the XOR of
    // the carryless products the reference accumulated.
    private static final byte[] GF4_MUL = new byte[256];

    // Precomputed MixColumn per-column spread table: PHOTON_COL[(k << 4) | v] packs the contribution
    // of state nibble value v at row k into a 32-bit column, where nibble i (bits [4i, 4i+4)) holds
    // MixColMatrix[i][k] (x) v in GF(2^4). A MixColumn output column j is then the XOR over k of
    // PHOTON_COL[k][in[k][j]] - 8 table lookups + 7 XORs, vs the reference's 64 GF products per
    // column. Byte-identical: nibbles occupy disjoint bit-fields so the packed XOR equals the
    // per-nibble GF(2^4) sum the column would compute element-wise.
    private static final int[] PHOTON_COL = new int[8 * 16];

    static
    {
        for (int x = 0; x < 16; x++)
        {
            for (int b = 0; b < 16; b++)
            {
                int sum = x * (b & 1) ^ x * (b & 2) ^ x * (b & 4) ^ x * (b & 8);
                int t0 = sum >>> 4;
                sum = (sum & 15) ^ t0 ^ (t0 << 1);
                int t1 = sum >>> 4;
                sum = (sum & 15) ^ t1 ^ (t1 << 1);
                GF4_MUL[(x << 4) | b] = (byte)sum;
            }
        }
        for (int k = 0; k < D; k++)
        {
            for (int v = 0; v < 16; v++)
            {
                int packed = 0;
                for (int i = 0; i < D; i++)
                {
                    int prod = GF4_MUL[((MixColMatrix[i][k] & 0xF) << 4) | v] & 0xF;
                    packed |= prod << (i << 2);
                }
                PHOTON_COL[(k << 4) | v] = packed;
            }
        }
    }

    public PhotonBeetleEngine(PhotonBeetleParameters pbp)
    {
        KEY_SIZE = IV_SIZE = MAC_SIZE = 16;
        int CAPACITY_INBITS = 0, RATE_INBITS = 0;
        switch (pbp)
        {
        case pb32:
            RATE_INBITS = 32;
            CAPACITY_INBITS = 224;
            break;
        case pb128:
            RATE_INBITS = 128;
            CAPACITY_INBITS = 128;
            break;
        }
        AADBufferSize = BlockSize = (RATE_INBITS + 7) >>> 3;
        RATE_INBYTES_HALF = BlockSize >>> 1;
        int STATE_INBITS = RATE_INBITS + CAPACITY_INBITS;
        STATE_INBYTES = (STATE_INBITS + 7) >>> 3;
        LAST_THREE_BITS_OFFSET = (STATE_INBITS - ((STATE_INBYTES - 1) << 3) - 3);
        algorithmName = "Photon-Beetle AEAD";
        state = new byte[STATE_INBYTES];
        setInnerMembers(ProcessingBufferType.Buffered, AADOperatorType.Counter, DataOperatorType.Counter);
    }

    @Override
    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        K = key;
        N = iv;
    }

    protected void processBufferAAD(byte[] input, int inOff)
    {
        photonPermutation(state);
        Bytes.xorTo(BlockSize, input, inOff, state);
    }

    @Override
    protected void finishAAD(State nextState, boolean isDoFinal)
    {
        finishAAD3(nextState, isDoFinal);
    }

    protected void processFinalAAD()
    {
        int aadLen = aadOperator.getLen();
        if (aadLen != 0)
        {
            if (m_aadPos != 0)
            {
                photonPermutation(state);
                Bytes.xorTo(m_aadPos, m_aad, state);
                if (m_aadPos < BlockSize)
                {
                    state[m_aadPos] ^= 0x01; // ozs
                }
            }
            state[STATE_INBYTES - 1] ^= select(dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE) > 0,
                ((aadLen % BlockSize) == 0), (byte)3, (byte)4) << LAST_THREE_BITS_OFFSET;
        }
    }

    protected void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        rhoohr(output, outOff, input, inOff, BlockSize);
        Bytes.xorTo(BlockSize, input, inOff, state);
    }

    protected void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        rhoohr(output, outOff, input, inOff, BlockSize);
        Bytes.xorTo(BlockSize, output, outOff, state);
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        int len = dataOperator.getLen() - (forEncryption ? 0 : MAC_SIZE);
        int bufferLen = m_bufPos;// - (forEncryption ? 0 : MAC_SIZE);
        int aadLen = aadOperator.getLen();
        if (aadLen != 0 || len != 0)
        {
            input_empty = false;
        }
        byte c1 = select((aadLen != 0), ((len % BlockSize) == 0), (byte)5, (byte)6);

        if (len != 0)
        {
            if (bufferLen != 0)
            {
                rhoohr(output, outOff, m_buf, 0, bufferLen);
                if (forEncryption)
                {
                    Bytes.xorTo(bufferLen, m_buf, state);
                }
                else
                {
                    Bytes.xorTo(bufferLen, output, outOff, state);
                }
                if (bufferLen < BlockSize)
                {
                    state[bufferLen] ^= 0x01; // ozs
                }
            }
            state[STATE_INBYTES - 1] ^= c1 << LAST_THREE_BITS_OFFSET;
        }
        else if (input_empty)
        {
            state[STATE_INBYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        }
        photonPermutation(state);
        System.arraycopy(state, 0, mac, 0, MAC_SIZE);
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        input_empty = true;
        System.arraycopy(K, 0, state, 0, K.length);
        System.arraycopy(N, 0, state, K.length, N.length);
    }

    private static void photonPermutation(byte[] state)
    {
        int i, j, k;
        // Flattened 8x8 nibble state: cell (row, col) at s2[(row << 3) + col]. Single byte[64]
        // instead of byte[8][8] - removes the per-call inner-array allocations and 2D pointer-chase.
        byte[] s2 = new byte[64];
        byte[] tmp8 = new byte[D];
        for (i = 0; i < 64; i++)
        {
            s2[i] = (byte)(((state[i >> 1] & 0xFF) >>> ((i & 1) << 2)) & 0xf);
        }
        int ROUND = 12;
        for (int round = 0; round < ROUND; round++)
        {
            //AddKey
            for (i = 0; i < D; i++)
            {
                s2[i << 3] ^= RC[i][round];
            }
            //SubCell
            for (i = 0; i < 64; i++)
            {
                s2[i] = sbox[s2[i]];
            }
            //ShiftRow (row i rotated left by i)
            for (i = 1; i < D; i++)
            {
                int base = i << 3;
                System.arraycopy(s2, base, tmp8, 0, D);
                for (int c = 0; c < D; c++)
                {
                    s2[base + c] = tmp8[(c + i) & 7];
                }
            }
            //MixColumn (per-column spread table: outCol = XOR over rows k of PHOTON_COL[k][in[k][j]])
            for (j = 0; j < D; j++)
            {
                int col = 0;
                for (k = 0; k < D; k++)
                {
                    col ^= PHOTON_COL[(k << 4) | (s2[(k << 3) + j] & 0xF)];
                }
                for (i = 0; i < D; i++)
                {
                    s2[(i << 3) + j] = (byte)((col >>> (i << 2)) & 0xF);
                }
            }
        }
        for (i = 0; i < 64; i += 2)
        {
            state[i >>> 1] = (byte)((s2[i] & 0xf) | ((s2[i + 1] & 0xf) << 4));
        }
    }

    private byte select(boolean condition1, boolean condition2, byte option3, byte option4)
    {
        if (condition1 && condition2)
        {
            return 1;
        }
        if (condition1)
        {
            return 2;
        }
        if (condition2)
        {
            return option3;
        }
        return option4;
    }

    private void rhoohr(byte[] ciphertext, int outOff, byte[] plaintext, int inOff, int DBlen_inbytes)
    {
        photonPermutation(state);
        byte[] OuterState_part1_ROTR1 = new byte[D];
        int i, loop_end = Math.min(DBlen_inbytes, RATE_INBYTES_HALF);
        for (i = 0; i < RATE_INBYTES_HALF - 1; i++)
        {
            OuterState_part1_ROTR1[i] = (byte)(((state[i] & 0xFF) >>> 1) | ((state[(i + 1)] & 1) << 7));
        }
        OuterState_part1_ROTR1[RATE_INBYTES_HALF - 1] = (byte)(((state[i] & 0xFF) >>> 1) | ((state[0] & 1) << 7));
        Bytes.xor(loop_end, state, RATE_INBYTES_HALF, plaintext, inOff, ciphertext, outOff);
        Bytes.xor(DBlen_inbytes - loop_end, OuterState_part1_ROTR1, loop_end - RATE_INBYTES_HALF, plaintext,
            inOff + loop_end, ciphertext, outOff + loop_end);
    }

    public static void photonPermutation(PhotonBeetleDigest.Friend friend, byte[] state)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by PhotonBeetleDigest");
        }

        photonPermutation(state);
    }
}