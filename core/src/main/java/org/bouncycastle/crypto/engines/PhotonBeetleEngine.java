package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class PhotonBeetleEngine
    implements AEADBlockCipher
{
    public enum PhotonBeetleParameters
    {
        pb32, pb128
    }

    private byte[] K;
    private byte[] N;
    private byte[] state;
    private byte[] A;
    private byte[] M;
    private byte[] C;
    private byte[] T;
    private int CRYPTO_KEYBYTES = 16;
    private int CRYPTO_NPUBBYTES = 16;
    private int RATE_INBITS;
    private int RATE_INBYTES;
    private int SQUEEZE_RATE_INBITS = 128;
    private int SQUEEZE_RATE_INBYTES = ((SQUEEZE_RATE_INBITS + 7) / 8);
    private int CAPACITY_INBITS;
    private int STATE_INBITS;
    private int STATE_INBYTES;
    private int KEY_INBYTES = CRYPTO_KEYBYTES;
    private int NOUNCE_INBYTES = CRYPTO_NPUBBYTES;
    private int TAG_INBITS = 128;
    private int TAG_INBYTES = ((TAG_INBITS + 7) / 8);
    private int LAST_THREE_BITS_OFFSET;
    private int ENC = 0;
    private int ROUND = 12;
    private int D = 8;
    private int S = 4;
    private final byte ReductionPoly = 0x3;
    private final byte WORDFILTER = (byte)((1 << S) - 1);
    private byte[][] RC = {
        {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
        {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
        {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
        {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
        {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
        {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
        {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
        {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
    };
    private byte[][] MixColMatrix = {
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

    public PhotonBeetleEngine(PhotonBeetleParameters pbp)
    {
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
        RATE_INBYTES = ((RATE_INBITS + 7) / 8);
        STATE_INBITS = (RATE_INBITS + CAPACITY_INBITS);
        STATE_INBYTES = ((STATE_INBITS + 7) / 8);
        LAST_THREE_BITS_OFFSET = (STATE_INBITS - (STATE_INBYTES - 1) * 8 - 3);
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
        /**
         * Grain encryption and decryption is completely symmetrical, so the
         * 'forEncryption' is irrelevant.
         */
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV)params;

        N = ivParams.getIV();

        if (N == null || N.length != NOUNCE_INBYTES)
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD requires exactly 12 bytes of IV");
        }

        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD init parameters must include a key");
        }

        KeyParameter key = (KeyParameter)ivParams.getParameters();
        K = key.getKey();
        if (K.length != KEY_INBYTES)
        {
            throw new IllegalArgumentException(
                "Grain-128AEAD key must be 128 bits long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));

        state = new byte[STATE_INBYTES];
        T = new byte[TAG_INBYTES];
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Photon-Beetle AEAD";
    }

    @Override
    public void processAADByte(byte in)
    {

    }

    @Override
    public void processAADBytes(byte[] in, int inOff, int len)
    {
        A = in;
    }

    @Override
    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        return 0;
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        M = in;
        return 0;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        int mlen = M.length;
        int adlen = A.length;
        if ((A.length == 0) && (M.length == 0))
        {
            state[STATE_INBYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
            TAG(T, state);
            System.arraycopy(T, 0, output, 0, T.length);
            return TAG_INBYTES;
        }
        byte c0 = select((mlen != 0), ((adlen % RATE_INBYTES) == 0), (byte)3, (byte)4);
        byte c1 = select((adlen != 0), ((mlen % RATE_INBYTES) == 0), (byte)5, (byte)6);
        int i, Dlen_inblocks, LastDBlocklen;
        if (adlen != 0)
        {
            Dlen_inblocks = (adlen + RATE_INBYTES - 1) / RATE_INBYTES;
            for (i = 0; i < Dlen_inblocks - 1; i++)
            {
                PHOTON_Permutation(state);
                XOR(state, state, A, i * RATE_INBYTES, RATE_INBYTES);
            }
            PHOTON_Permutation(state);
            LastDBlocklen = adlen - i * RATE_INBYTES;
            XOR(state, state, A, i * RATE_INBYTES, LastDBlocklen);
            if (LastDBlocklen < RATE_INBYTES)
            {
                state[LastDBlocklen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= c0 << LAST_THREE_BITS_OFFSET;
        }
        if (mlen != 0)
        {
            Dlen_inblocks = (mlen + RATE_INBYTES - 1) / RATE_INBYTES;
            for (i = 0; i < Dlen_inblocks - 1; i++)
            {
                PHOTON_Permutation(state);
                rhoohr(state, output, i * RATE_INBYTES, M, i * RATE_INBYTES, RATE_INBYTES, ENC);
            }
            PHOTON_Permutation(state);
            LastDBlocklen = mlen - i * RATE_INBYTES;
            rhoohr(state, output, i * RATE_INBYTES, M, i * RATE_INBYTES, LastDBlocklen, ENC);
            if (LastDBlocklen < RATE_INBYTES)
            {
                state[LastDBlocklen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= c1 << LAST_THREE_BITS_OFFSET;
        }
        TAG(T, state);
        System.arraycopy(T, 0, output, M.length, T.length);
        return M.length + TAG_INBYTES;
    }

    @Override
    public byte[] getMac()
    {
        return T;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    @Override
    public int getOutputSize(int len)
    {
        return len + 16;
    }

    @Override
    public void reset()
    {
        System.arraycopy(K, 0, state, 0, K.length);
        System.arraycopy(N, 0, state, K.length, N.length);
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
        int i, j, k, l;
        for (i = 0; i < D * D; i++)
        {
            state[i / D][i % D] = (byte)(((State_in[i / 2] & 0xFF) >>> (4 * (i & 1))) & 0xf);
        }
        byte[] tmp = new byte[D];
        for (int round = 0; round < ROUND; round++)
        {
            //AddKey;
            for (i = 0; i < D; i++)
            {
                state[i][0] ^= RC[i][round];
            }
            //SubCell
            for (i = 0; i < D; i++)
            {
                for (j = 0; j < D; j++)
                {
                    state[i][j] = sbox[state[i][j]];
                }
            }
            //ShiftRow
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
            //MixColumn
            for (j = 0; j < D; j++)
            {
                for (i = 0; i < D; i++)
                {
                    byte sum = 0;
                    for (k = 0; k < D; k++)
                    {
                        int x = MixColMatrix[i][k], ret = 0, b = state[k][j];
                        for (l = 0; l < S; l++)
                        {
                            if (((b >>> l) & 1) != 0)
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
                        sum ^= (ret & WORDFILTER);
                    }
                    tmp[i] = sum;
                }
                for (i = 0; i < D; i++)
                {
                    state[i][j] = tmp[i];
                }
            }
        }
        Arrays.fill(State_in, 0, (D * D) / 2, (byte)0);
        for (i = 0; i < D * D; i++)
        {
            State_in[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
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

    void rhoohr(byte[] OuterState_inout, byte[] DataBlock_out, int dbo_off, byte[] DataBlock_in, int dbi_off, int DBlen_inbytes, int EncDecInd)
    {
        int OuterState_part2_idx = RATE_INBYTES / 2;
        byte[] OuterState_part1_ROTR1 = new byte[OuterState_part2_idx];
        int i;
        byte tmp = OuterState_inout[0];
        for (i = 0; i < OuterState_part2_idx - 1; i++)
        {
            OuterState_part1_ROTR1[i] = (byte)(((OuterState_inout[i] & 0xFF) >>> 1) | ((OuterState_inout[(i + 1)] & 1) << 7));
        }
        OuterState_part1_ROTR1[OuterState_part2_idx - 1] = (byte)(((OuterState_inout[i] & 0xFF) >>> 1) | ((tmp & 1) << 7));
        i = 0;
        while ((i < DBlen_inbytes) && (i < RATE_INBYTES / 2))
        {
            DataBlock_out[i + dbo_off] = (byte)(OuterState_inout[i + OuterState_part2_idx] ^ DataBlock_in[i + dbi_off]);
            i++;
        }
        while (i < DBlen_inbytes)
        {
            DataBlock_out[i + dbo_off] = (byte)(OuterState_part1_ROTR1[i - RATE_INBYTES / 2] ^ DataBlock_in[i + dbi_off]);
            i++;
        }

        if (EncDecInd == ENC)
        {
            XOR(OuterState_inout, OuterState_inout, DataBlock_in, dbi_off, DBlen_inbytes);
        }
        else
        {
            XOR(OuterState_inout, OuterState_inout, DataBlock_out, dbo_off, DBlen_inbytes);
        }
    }

    void XOR(byte[] out, byte[] in_left, byte[] in_right, int rOff, int iolen_inbytes)
    {
        for (int i = 0; i < iolen_inbytes; i++)
        {
            out[i] = (byte)(in_left[i] ^ in_right[i + rOff]);
        }
    }
}
