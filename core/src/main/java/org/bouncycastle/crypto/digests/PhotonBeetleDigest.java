package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

public class PhotonBeetleDigest
    implements Digest
{
    private byte[] state;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int CRYPTO_KEYBYTES = 16;
    private int CRYPTO_NSECBYTES = 0;
    private int INITIAL_RATE_INBITS = 128;
    private int INITIAL_RATE_INBYTES = ((INITIAL_RATE_INBITS + 7) / 8);
    private int CRYPTO_NPUBBYTES = 16;
    private int CRYPTO_ABYTES = 16;
    private int CRYPTO_NOOVERLAP = 1;
    private int RATE_INBITS;
    private int RATE_INBYTES;
    private int SQUEEZE_RATE_INBITS = 128;
    private int SQUEEZE_RATE_INBYTES = ((SQUEEZE_RATE_INBITS + 7) / 8);
    private int CAPACITY_INBITS;
    private int CAPACITY_INBYTES;
    private int STATE_INBITS;
    private int STATE_INBYTES;
    private int KEY_INBITS;
    private int KEY_INBYTES = CRYPTO_KEYBYTES;
    private int NOUNCE_INBYTES = CRYPTO_NPUBBYTES;
    private int TAG_INBITS = 256;
    private int TAG_INBYTES = ((TAG_INBITS + 7) / 8);
    private int LAST_THREE_BITS_OFFSET;
    private int ENC = 0;
    private int DEC = 1;
    private int ROUND = 12;
    private int D = 8;
    private int S = 4;
    private final byte ReductionPoly = 0x3;
    private final byte WORDFILTER = (byte)((1 << S) - 1);
    private byte[][] RC = {//[D][12]
        {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
        {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
        {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
        {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
        {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
        {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
        {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
        {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
    };
    private byte[][] MixColMatrix = { //[D][D]
        {2, 4, 2, 11, 2, 8, 5, 6},
        {12, 9, 8, 13, 7, 7, 5, 2},
        {4, 4, 13, 13, 9, 4, 13, 9},
        {1, 6, 5, 1, 12, 13, 15, 14},
        {15, 12, 9, 13, 14, 5, 14, 13},
        {9, 14, 5, 15, 4, 12, 9, 6},
        {12, 2, 2, 10, 3, 1, 1, 14},
        {15, 1, 13, 10, 5, 10, 2, 3}
    };

    private byte[] sbox = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

    public PhotonBeetleDigest()
    {
        RATE_INBITS = 32;
        CAPACITY_INBITS = 224;
        RATE_INBYTES = ((RATE_INBITS + 7) / 8);
        CAPACITY_INBYTES = ((CAPACITY_INBITS + 7) / 8);
        STATE_INBITS = (RATE_INBITS + CAPACITY_INBITS);
        STATE_INBYTES = ((STATE_INBITS + 7) / 8);
        KEY_INBITS = (CRYPTO_KEYBYTES * 8);
        LAST_THREE_BITS_OFFSET = (STATE_INBITS - (STATE_INBYTES - 1) * 8 - 3);
    }

    @Override
    public String getAlgorithmName()
    {
        return null;
    }

    @Override
    public int getDigestSize()
    {
        return 0;
    }

    @Override
    public void update(byte input)
    {
        buffer.write(input);
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        buffer.write(input, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff)
    {
        byte[] State = new byte[STATE_INBYTES];
        byte c0;
        byte[] input = buffer.toByteArray();
        int inlen = input.length;
        if (inlen == 0)
        {
            XOR_const(State, (byte)1);
        }
        else if (inlen <= INITIAL_RATE_INBYTES)
        {
            c0 = select((inlen < INITIAL_RATE_INBYTES), (byte)1, (byte)2);
            System.arraycopy(input, 0, State, 0, inlen);
            if (inlen < INITIAL_RATE_INBYTES)
            {
                State[inlen] ^= 0x01; // ozs
            }
            XOR_const(State, c0);
        }
        else
        {
            System.arraycopy(input, 0, State, 0, INITIAL_RATE_INBYTES);
            inlen -= INITIAL_RATE_INBYTES;
            c0 = select((inlen % RATE_INBYTES) == 0, (byte)1, (byte)2);
            HASH(State, input, INITIAL_RATE_INBYTES, inlen, c0);
        }
        TAG(out, State);
        return 0;
    }

    @Override
    public void reset()
    {
        buffer.reset();
    }

    private void XOR_const(byte[] State_inout, byte ant)
    {
        State_inout[STATE_INBYTES - 1] ^= ((ant & 0xFF) << LAST_THREE_BITS_OFFSET);
    }

    private void TAG(byte[] Tag_out, byte[] State)
    {
        int i = TAG_INBYTES;
        int Tag_out_idx = 0;
        while (i > SQUEEZE_RATE_INBYTES)
        {
            PHOTON_Permutation(State);
            System.arraycopy(State, 0, Tag_out, Tag_out_idx, SQUEEZE_RATE_INBYTES);
            Tag_out_idx += SQUEEZE_RATE_INBYTES;
            i -= SQUEEZE_RATE_INBYTES;
        }
        PHOTON_Permutation(State);
        System.arraycopy(State, 0, Tag_out, Tag_out_idx, i);
    }

    void PHOTON_Permutation(byte[] State_in)
    {
        byte[][] state = new byte[D][D];
        int i;
        for (i = 0; i < D * D; i++)
        {
            state[i / D][i % D] = (byte)(((State_in[i / 2] & 0xFF) >>> (4 * (i & 1))) & 0xf);
        }
        Permutation(state, ROUND);
        Arrays.fill(State_in, 0, (D * D) / 2, (byte)0);
        for (i = 0; i < D * D; i++)
        {
            State_in[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
        }
    }


    private byte select(boolean condition, byte option1, byte option2)
    {
        if (condition)
        {
            return option1;
        }
        return option2;
    }

    private void HASH(byte[] State, byte[] Data_in, int Data_in_off, int Dlen_inbytes, byte ant)
    {
        int Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
        int LastDBlocklen;
        int i;

        for (i = 0; i < Dlen_inblocks - 1; i++)
        {
            PHOTON_Permutation(State);
            XOR(State, State, 0, Data_in, Data_in_off + i * RATE_INBYTES, RATE_INBYTES);
        }
        PHOTON_Permutation(State);
        LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
        XOR(State, State, 0, Data_in, Data_in_off + i * RATE_INBYTES, LastDBlocklen);
        if (LastDBlocklen < RATE_INBYTES)
        {
            State[LastDBlocklen] ^= 0x01; // ozs
        }

        XOR_const(State, ant);
    }

    private void ENCorDEC(byte[] State_inout, byte[] Data_out, byte[] Data_in, int Dlen_inbytes, byte ant, int EncDecInd)
    {
        byte[] State = State_inout;
        int Dlen_inblocks = (Dlen_inbytes + RATE_INBYTES - 1) / RATE_INBYTES;
        int LastDBlocklen;
        int i;

        for (i = 0; i < Dlen_inblocks - 1; i++)
        {
            PHOTON_Permutation(State);
            rhoohr(State, Data_out, i * RATE_INBYTES, Data_in, i * RATE_INBYTES, RATE_INBYTES, EncDecInd);
        }
        PHOTON_Permutation(State);
        LastDBlocklen = Dlen_inbytes - i * RATE_INBYTES;
        rhoohr(State, Data_out, i * RATE_INBYTES, Data_in, i * RATE_INBYTES, LastDBlocklen, EncDecInd);
        if (LastDBlocklen < RATE_INBYTES)
        {
            State[LastDBlocklen] ^= 0x01; // ozs
        }

        XOR_const(State, ant);
    }

    void rhoohr(byte[] OuterState_inout, byte[] DataBlock_out, int dbo_off, byte[] DataBlock_in, int dbi_off, int DBlen_inbytes, int EncDecInd)
    {
        ShuffleXOR(DataBlock_out, dbo_off, OuterState_inout, 0, DataBlock_in, dbi_off, DBlen_inbytes);
        if (EncDecInd == ENC)
        {
            XOR(OuterState_inout, OuterState_inout, 0, DataBlock_in, dbi_off, DBlen_inbytes);
        }
        else
        {
            XOR(OuterState_inout, OuterState_inout, 0, DataBlock_out, dbo_off, DBlen_inbytes);
        }
    }

    void XOR(byte[] out, byte[] in_left, int lOff, byte[] in_right, int rOff, int iolen_inbytes)
    {
        for (int i = 0; i < iolen_inbytes; i++)
        {
            out[i] = (byte)(in_left[i + lOff] ^ in_right[i + rOff]);
        }
    }

    void ShuffleXOR(byte[] DataBlock_out, int dbo_off, byte[] OuterState_in, int osi_off, byte[] DataBlock_in, int dbi_off, int DBlen_inbytes)
    {
        int OuterState_part2_idx = osi_off + RATE_INBYTES / 2;
        byte[] OuterState_part1_ROTR1 = new byte[RATE_INBYTES / 2];
        int i;
        ROTR1(OuterState_part1_ROTR1, OuterState_in, osi_off, RATE_INBYTES / 2);
        i = 0;
        while ((i < DBlen_inbytes) && (i < RATE_INBYTES / 2))
        {
            DataBlock_out[i + dbo_off] = (byte)(OuterState_in[i + OuterState_part2_idx] ^ DataBlock_in[i + dbi_off]);
            i++;
        }
        while (i < DBlen_inbytes)
        {
            DataBlock_out[i + dbo_off] = (byte)(OuterState_part1_ROTR1[i - RATE_INBYTES / 2] ^ DataBlock_in[i + dbi_off]);
            i++;
        }
    }

    void ROTR1(byte[] output, byte[] input, int inOff, int iolen_inbytes)
    {
        byte tmp = input[inOff];
        int i;
        for (i = 0; i < iolen_inbytes - 1; i++)
        {
            output[i] = (byte)(((input[inOff + i] & 0xFF) >>> 1) | ((input[(inOff + i + 1)] & 1) << 7));
        }
        output[iolen_inbytes - 1] = (byte)(((input[inOff + i] & 0xFF) >>> 1) | ((tmp & 1) << 7));
    }

    void Permutation(byte[][] state, int R)
    {
        int i;
        for (i = 0; i < R; i++)
        {
            //if(DEBUG) printf("--- Round %d ---\n", i);
            AddKey(state, i); //PrintState(state);
            SubCell(state); //PrintState(state);
            ShiftRow(state); //PrintState(state);
            MixColumn(state);
            //PrintState(state);
        }
    }

    void AddKey(byte[][] state, int round)
    {
        for (int i = 0; i < D; i++)
        {
            state[i][0] ^= RC[i][round];
        }
    }

    void SubCell(byte[][] state)
    {
        int i, j;
        for (i = 0; i < D; i++)
        {
            for (j = 0; j < D; j++)
            {
                state[i][j] = sbox[state[i][j]];
            }
        }
    }

    void ShiftRow(byte[][] state)
    {
        int i, j;
        byte[] tmp = new byte[D];
        for (i = 1; i < D; i++)
        {
            for (j = 0; j < D; j++)
            {
                tmp[j] = state[i][j];
            }
            for (j = 0; j < D; j++)
            {
                state[i][j] = tmp[(j + i) % D];
            }
        }
    }

    void MixColumn(byte[][] state)
    {
        int i, j, k;
        byte[] tmp = new byte[D];
        for (j = 0; j < D; j++)
        {
            for (i = 0; i < D; i++)
            {
                byte sum = 0;
                for (k = 0; k < D; k++)
                {
                    sum ^= FieldMult(MixColMatrix[i][k], state[k][j]);
                }
                tmp[i] = sum;
            }
            for (i = 0; i < D; i++)
            {
                state[i][j] = tmp[i];
            }
        }
    }

    byte FieldMult(byte a, byte b)
    {
        int x = a, ret = 0;
        int i;
        for (i = 0; i < S; i++)
        {
            if (((b >>> i) & 1) != 0)
            {
                ret ^= x;
            }
            if (((x >>> (S - 1)) & 1) != 0)
            {
                x <<= 1;
                x ^= ReductionPoly;
            }
            else
            {
                x <<= 1;
            }
        }
        return (byte)(ret & WORDFILTER);
    }
}
