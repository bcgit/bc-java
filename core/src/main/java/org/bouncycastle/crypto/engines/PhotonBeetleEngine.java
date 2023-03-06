package org.bouncycastle.crypto.engines;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Photon-Beetle, https://www.isical.ac.in/~lightweight/beetle/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
 * <p>
 * Photon-Beetle with reference to C Reference Impl from: https://github.com/PHOTON-Beetle/Software
 * </p>
 */

public class PhotonBeetleEngine
    implements AEADCipher
{
    public enum PhotonBeetleParameters
    {
        pb32,
        pb128
    }

    private boolean input_empty;
    private boolean forEncryption;
    private byte[] K;
    private byte[] N;
    private byte[] state;
    private byte[][] state_2d;
    private byte[] A;
    private byte[] T;
    private boolean encrypted;
    private boolean initialised;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private final int CRYPTO_KEYBYTES = 16;
    private final int CRYPTO_NPUBBYTES = 16;
    private final int RATE_INBYTES;
    private final int RATE_INBYTES_HALF;
    private final int STATE_INBYTES;
    private final int TAG_INBYTES = 16;
    private final int LAST_THREE_BITS_OFFSET;
    private final int ROUND = 12;
    private final int D = 8;
    private final int Dq = 3;
    private final int Dr = 7;
    private final int DSquare = 64;
    private final int S = 4;
    private final int S_1 = 3;
    private final byte[][] RC = {
        {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
        {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
        {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
        {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
        {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
        {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
        {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
        {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
    };
    private final byte[][] MixColMatrix = {
        {2, 4, 2, 11, 2, 8, 5, 6},
        {12, 9, 8, 13, 7, 7, 5, 2},
        {4, 4, 13, 13, 9, 4, 13, 9},
        {1, 6, 5, 1, 12, 13, 15, 14},
        {15, 12, 9, 13, 14, 5, 14, 13},
        {9, 14, 5, 15, 4, 12, 9, 6},
        {12, 2, 2, 10, 3, 1, 1, 14},
        {15, 1, 13, 10, 5, 10, 2, 3}
    };

    private final byte[] sbox = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

    public PhotonBeetleEngine(PhotonBeetleParameters pbp)
    {
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
        RATE_INBYTES = (RATE_INBITS + 7) >>> 3;
        RATE_INBYTES_HALF = RATE_INBYTES >>> 1;
        int STATE_INBITS = RATE_INBITS + CAPACITY_INBITS;
        STATE_INBYTES = (STATE_INBITS + 7) >>> 3;
        LAST_THREE_BITS_OFFSET = (STATE_INBITS - ((STATE_INBYTES - 1) << 3) - 3);
        initialised = false;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException("Photon-Beetle AEAD init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV)params;
        N = ivParams.getIV();
        if (N == null || N.length != CRYPTO_NPUBBYTES)
        {
            throw new IllegalArgumentException("Photon-Beetle AEAD requires exactly 16 bytes of IV");
        }
        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException("Photon-Beetle AEAD init parameters must include a key");
        }
        KeyParameter key = (KeyParameter)ivParams.getParameters();
        K = key.getKey();
        if (K.length != CRYPTO_KEYBYTES)
        {
            throw new IllegalArgumentException("Photon-Beetle AEAD key must be 128 bits long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        state = new byte[STATE_INBYTES];
        state_2d = new byte[D][D];
        T = new byte[TAG_INBYTES];
        initialised = true;
        reset(false);
    }

    @Override
    public String getAlgorithmName()
    {
        return "Photon-Beetle AEAD";
    }

    @Override
    public void processAADByte(byte input)
    {
        aadData.write(input);
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        aadData.write(input, inOff, len);
    }

    @Override
    public int processByte(byte input, byte[] output, int outOff)
        throws DataLengthException
    {
        return processBytes(new byte[]{input}, 0, 1, output, outOff);
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        message.write(input, inOff, len);
        return 0;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        int len = message.size() - (forEncryption ? 0 : TAG_INBYTES);
        if ((forEncryption && len + TAG_INBYTES + outOff > output.length) ||
            (!forEncryption && len + outOff > output.length))
        {
            throw new OutputLengthException("output buffer too short");
        }
        byte[] input = message.toByteArray();
        int inOff = 0;
        A = aadData.toByteArray();
        int adlen = A.length, i;
        if (adlen != 0 || len != 0)
        {
            input_empty = false;
        }
        byte c0 = select((len != 0), ((adlen % RATE_INBYTES) == 0), (byte)3, (byte)4);
        byte c1 = select((adlen != 0), ((len % RATE_INBYTES) == 0), (byte)5, (byte)6);
        int Dlen_inblocks, LastDBlocklen;
        if (adlen != 0)
        {
            Dlen_inblocks = (adlen + RATE_INBYTES - 1) / RATE_INBYTES;
            for (i = 0; i < Dlen_inblocks - 1; i++)
            {
                PHOTON_Permutation();
                XOR(A, i * RATE_INBYTES, RATE_INBYTES);
            }
            PHOTON_Permutation();
            LastDBlocklen = adlen - i * RATE_INBYTES;
            XOR(A, i * RATE_INBYTES, LastDBlocklen);
            if (LastDBlocklen < RATE_INBYTES)
            {
                state[LastDBlocklen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= c0 << LAST_THREE_BITS_OFFSET;
        }
        if (len != 0)
        {
            Dlen_inblocks = (len + RATE_INBYTES - 1) / RATE_INBYTES;
            for (i = 0; i < Dlen_inblocks - 1; i++)
            {
                PHOTON_Permutation();
                rhoohr(output, outOff + i * RATE_INBYTES, input, inOff + i * RATE_INBYTES, RATE_INBYTES);
            }
            PHOTON_Permutation();
            LastDBlocklen = len - i * RATE_INBYTES;
            rhoohr(output, outOff + i * RATE_INBYTES, input, inOff + i * RATE_INBYTES, LastDBlocklen);
            if (LastDBlocklen < RATE_INBYTES)
            {
                state[LastDBlocklen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= c1 << LAST_THREE_BITS_OFFSET;
        }
        outOff += len;
        if (input_empty)
        {
            state[STATE_INBYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        }
        PHOTON_Permutation();
        T = new byte[TAG_INBYTES];
        System.arraycopy(state, 0, T, 0, TAG_INBYTES);
        if (forEncryption)
        {
            System.arraycopy(T, 0, output, outOff, TAG_INBYTES);
            len += TAG_INBYTES;
        }
        else
        {
            for (i = 0; i < TAG_INBYTES; ++i)
            {
                if (T[i] != input[len + i])
                {
                    throw new IllegalArgumentException("Mac does not match");
                }
            }
        }
        reset(false);
        return len;
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
        return len + TAG_INBYTES;
    }

    @Override
    public void reset()
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }

        reset(true);
    }

    private void reset(boolean clearMac)
    {
        if (clearMac)
        {
            T = null;
        }
        input_empty = true;
        aadData.reset();
        message.reset();
        System.arraycopy(K, 0, state, 0, K.length);
        System.arraycopy(N, 0, state, K.length, N.length);
        encrypted = false;
    }

    private void PHOTON_Permutation()
    {
        int i, j, k, l;
        for (i = 0; i < DSquare; i++)
        {
            state_2d[i >>> Dq][i & Dr] = (byte)(((state[i >> 1] & 0xFF) >>> (4 * (i & 1))) & 0xf);
        }
        for (int round = 0; round < ROUND; round++)
        {
            //AddKey
            for (i = 0; i < D; i++)
            {
                state_2d[i][0] ^= RC[i][round];
            }
            //SubCell
            for (i = 0; i < D; i++)
            {
                for (j = 0; j < D; j++)
                {
                    state_2d[i][j] = sbox[state_2d[i][j]];
                }
            }
            //ShiftRow
            for (i = 1; i < D; i++)
            {
                System.arraycopy(state_2d[i], 0, state, 0, D);
                System.arraycopy(state, i, state_2d[i], 0, D - i);
                System.arraycopy(state, 0, state_2d[i], D - i, i);
            }
            //MixColumn
            for (j = 0; j < D; j++)
            {
                for (i = 0; i < D; i++)
                {
                    byte sum = 0;
                    for (k = 0; k < D; k++)
                    {
                        int x = MixColMatrix[i][k], ret = 0, b = state_2d[k][j];
                        for (l = 0; l < S; l++)
                        {
                            if (((b >>> l) & 1) != 0)
                            {
                                ret ^= x;
                            }
                            if (((x >>> S_1) & 1) != 0)
                            {
                                x <<= 1;
                                x ^= 0x3;
                            }
                            else
                            {
                                x <<= 1;
                            }
                        }
                        sum ^= ret & 15;
                    }
                    state[i] = sum;
                }
                for (i = 0; i < D; i++)
                {
                    state_2d[i][j] = state[i];
                }
            }
        }
        for (i = 0; i < DSquare; i += 2)
        {
            state[i >>> 1] = (byte)(((state_2d[i >>> Dq][i & Dr] & 0xf)) | ((state_2d[i >>> Dq][(i + 1) & Dr] & 0xf) << 4));
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
        byte[] OuterState_part1_ROTR1 = state_2d[0];
        int i, loop_end = Math.min(DBlen_inbytes, RATE_INBYTES_HALF);
        for (i = 0; i < RATE_INBYTES_HALF - 1; i++)
        {
            OuterState_part1_ROTR1[i] = (byte)(((state[i] & 0xFF) >>> 1) | ((state[(i + 1)] & 1) << 7));
        }
        OuterState_part1_ROTR1[RATE_INBYTES_HALF - 1] = (byte)(((state[i] & 0xFF) >>> 1) | ((state[0] & 1) << 7));
        i = 0;
        while (i < loop_end)
        {
            ciphertext[i + outOff] = (byte)(state[i + RATE_INBYTES_HALF] ^ plaintext[i++ + inOff]);
        }
        while (i < DBlen_inbytes)
        {
            ciphertext[i + outOff] = (byte)(OuterState_part1_ROTR1[i - RATE_INBYTES_HALF] ^ plaintext[i++ + inOff]);
        }
        if (forEncryption)
        {
            XOR(plaintext, inOff, DBlen_inbytes);
        }
        else
        {
            XOR(ciphertext, inOff, DBlen_inbytes);
        }
    }

    private void XOR(byte[] in_right, int rOff, int iolen_inbytes)
    {
        for (int i = 0; i < iolen_inbytes; i++)
        {
            state[i] ^= in_right[rOff++];
        }
    }

    public int getBlockSize()
    {
        return RATE_INBYTES;
    }

    public int getKeyBytesSize()
    {
        return CRYPTO_KEYBYTES;
    }

    public int getIVBytesSize()
    {
        return CRYPTO_NPUBBYTES;
    }
}
