package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;

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
    private byte[][] state_2d;
    private boolean initialised;
    private final byte[] buffer;
    private int bufferOff;
    private int aadLen;
    private int messageLen;
    private final int RATE_INBYTES;
    private final int RATE_INBYTES_HALF;
    private final int STATE_INBYTES;
    private final int LAST_THREE_BITS_OFFSET;
    private final int D = 8;
    private boolean aadFinished;
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
        KEY_SIZE = 16;
        IV_SIZE = 16;
        MAC_SIZE = 16;
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
        algorithmName = "Photon-Beetle AEAD";
        buffer = new byte[RATE_INBYTES + (forEncryption ? 0 : MAC_SIZE)];
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        byte[][] keyiv = initialize(forEncryption, params);
        K = keyiv[0];
        N = keyiv[1];
        state = new byte[STATE_INBYTES];
        state_2d = new byte[D][D];
        mac = new byte[MAC_SIZE];
        initialised = true;
        reset(false);
    }

    @Override
    public void processAADByte(byte input)
    {
        if (bufferOff >= RATE_INBYTES)
        {
            PHOTON_Permutation();
            XOR(buffer, 0, RATE_INBYTES);
            bufferOff = 0;
        }
        buffer[bufferOff++] = input;
        aadLen++;
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        int tmp;
        aadLen += len;
        if (bufferOff + len >= RATE_INBYTES)
        {
            tmp = RATE_INBYTES - bufferOff;
            System.arraycopy(input, inOff, buffer, bufferOff, tmp);
            PHOTON_Permutation();
            XOR(buffer, 0, RATE_INBYTES);
            inOff += tmp;
            len -= tmp;
            bufferOff = 0;
        }
        while (len >= RATE_INBYTES)
        {
            PHOTON_Permutation();
            XOR(input, inOff, RATE_INBYTES);
            inOff += RATE_INBYTES;
            len -= RATE_INBYTES;
        }
        System.arraycopy(input, inOff, buffer, bufferOff, len);
        bufferOff += len;
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        messageLen += len;
        // bufferOff will be set back to 0 if processFinalAADBlock is processed
        processFinalAADBlock(messageLen - (forEncryption ? 0 : MAC_SIZE) > 0);
        int blockLen = len + bufferOff - (forEncryption ? 0 : MAC_SIZE);
        int tmp;
        int rv = 0;

        int originalInOff = inOff;
        if (!forEncryption && bufferOff >= RATE_INBYTES)
        {
            PHOTON_Permutation();
            rhoohr(output, outOff, buffer, 0, RATE_INBYTES);
            rv += RATE_INBYTES;
            System.arraycopy(buffer, RATE_INBYTES, buffer, 0, bufferOff - RATE_INBYTES);
            bufferOff -= RATE_INBYTES;
            blockLen -= RATE_INBYTES;
            outOff += RATE_INBYTES;
        }
        if (blockLen >= RATE_INBYTES)
        {
            tmp = Math.max(RATE_INBYTES - bufferOff, 0);
            System.arraycopy(input, inOff, buffer, bufferOff, tmp);
            PHOTON_Permutation();
            rhoohr(output, outOff, buffer, 0, RATE_INBYTES);
            inOff += tmp;
            rv += RATE_INBYTES;
            blockLen -= RATE_INBYTES;
            outOff += RATE_INBYTES;
            bufferOff = 0;
        }
        while (blockLen >= RATE_INBYTES)
        {
            PHOTON_Permutation();
            rhoohr(output, outOff, input, inOff, RATE_INBYTES);
            outOff += RATE_INBYTES;
            inOff += RATE_INBYTES;
            rv += RATE_INBYTES;
            blockLen -= RATE_INBYTES;
        }
        len -= inOff - originalInOff;
        System.arraycopy(input, inOff, buffer, bufferOff, len);
        bufferOff += len;
        return rv;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        processFinalAADBlock(false);
        int len = messageLen - (forEncryption ? 0 : MAC_SIZE);
        int bufferLen = bufferOff - (forEncryption ? 0 : MAC_SIZE);
        if ((forEncryption && bufferLen + MAC_SIZE + outOff > output.length) ||
            (!forEncryption && bufferLen + outOff > output.length))
        {
            throw new OutputLengthException("output buffer too short");
        }
        int i;
        if (aadLen != 0 || len != 0)
        {
            input_empty = false;
        }
        byte c1 = select((aadLen != 0), ((len % RATE_INBYTES) == 0), (byte)5, (byte)6);

        if (len != 0)
        {
            if (bufferLen != 0)
            {
                PHOTON_Permutation();
                rhoohr(output, outOff, buffer, 0, bufferLen);
                state[bufferLen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= c1 << LAST_THREE_BITS_OFFSET;
        }
        outOff += bufferLen;
        if (input_empty)
        {
            state[STATE_INBYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        }
        PHOTON_Permutation();
        mac = new byte[MAC_SIZE];
        System.arraycopy(state, 0, mac, 0, MAC_SIZE);
        if (forEncryption)
        {
            System.arraycopy(mac, 0, output, outOff, MAC_SIZE);
            bufferLen += MAC_SIZE;
        }
        else
        {
            for (i = 0; i < MAC_SIZE; ++i)
            {
                if (mac[i] != buffer[bufferLen + i])
                {
                    throw new IllegalArgumentException("Mac does not match");
                }
            }
        }
        reset(false);
        return bufferLen;
    }

    private void processFinalAADBlock(boolean lenIsNotZero)
    {
        if (!aadFinished)
        {
            if (aadLen != 0)
            {
                if (bufferOff != 0)
                {
                    PHOTON_Permutation();
                    XOR(buffer, 0, bufferOff);
                    if (bufferOff < RATE_INBYTES)
                    {
                        state[bufferOff] ^= 0x01; // ozs
                    }
                }
                state[STATE_INBYTES - 1] ^= select(lenIsNotZero, ((aadLen % RATE_INBYTES) == 0), (byte)3, (byte)4) << LAST_THREE_BITS_OFFSET;
            }
            bufferOff = 0;
            aadFinished = true;
        }
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        int total;
        if (aadFinished)
        {
            total = Math.max(0, len + bufferOff + (forEncryption ? 0 : -MAC_SIZE));
        }
        else
        {
            total = Math.max(0, len + (forEncryption ? 0 : -MAC_SIZE));
        }
        return total - total % RATE_INBYTES;
    }

    @Override
    public int getOutputSize(int len)
    {
        if (aadFinished)
        {
            return Math.max(0, len + bufferOff + (forEncryption ? MAC_SIZE : -MAC_SIZE));
        }
        else
        {
            return Math.max(0, len + (forEncryption ? MAC_SIZE : -MAC_SIZE));
        }

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

    protected void reset(boolean clearMac)
    {
        input_empty = true;
        Arrays.fill(buffer, (byte)0);
        bufferOff = 0;
        aadLen = 0;
        aadFinished = false;
        messageLen = 0;
        System.arraycopy(K, 0, state, 0, K.length);
        System.arraycopy(N, 0, state, K.length, N.length);
        super.reset(clearMac);
    }

    private void PHOTON_Permutation()
    {
        int i, j, k;
        int dq = 3;
        int dr = 7;
        int DSquare = 64;
        for (i = 0; i < DSquare; i++)
        {
            state_2d[i >>> dq][i & dr] = (byte)(((state[i >> 1] & 0xFF) >>> (4 * (i & 1))) & 0xf);
        }
        int ROUND = 12;
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
                    int sum = 0;

                    for (k = 0; k < D; k++)
                    {
                        int x = MixColMatrix[i][k], b = state_2d[k][j];

                        sum ^= x * (b & 1);
                        sum ^= x * (b & 2);
                        sum ^= x * (b & 4);
                        sum ^= x * (b & 8);
                    }

                    int t0 = sum >>> 4;
                    sum = (sum & 15) ^ t0 ^ (t0 << 1);

                    int t1 = sum >>> 4;
                    sum = (sum & 15) ^ t1 ^ (t1 << 1);

                    state[i] = (byte)sum;
                }
                for (i = 0; i < D; i++)
                {
                    state_2d[i][j] = state[i];
                }
            }
        }
        for (i = 0; i < DSquare; i += 2)
        {
            state[i >>> 1] = (byte)(((state_2d[i >>> dq][i & dr] & 0xf)) | ((state_2d[i >>> dq][(i + 1) & dr] & 0xf) << 4));
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
            XOR(ciphertext, outOff, DBlen_inbytes);
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
}
