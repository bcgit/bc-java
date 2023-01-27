package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;

/**
 * Photon-Beetle, https://www.isical.ac.in/~lightweight/beetle/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf
 * <p>
 * Photon-Beetle with reference to C Reference Impl from: https://github.com/PHOTON-Beetle/Software
 * </p>
 */
public class PhotonBeetleDigest
    implements Digest
{
    private byte[] state;
    private byte[][] state_2d;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final int INITIAL_RATE_INBYTES = 16;
    private int RATE_INBYTES = 4;
    private int SQUEEZE_RATE_INBYTES = 16;
    private int STATE_INBYTES = 32;
    private int TAG_INBYTES = 32;
    private int LAST_THREE_BITS_OFFSET = 5;
    private int ROUND = 12;
    private int D = 8;
    private int Dq = 3;
    private int Dr = 7;
    private int DSquare = 64;
    private int S = 4;
    private int S_1 = 3;
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
        state = new byte[STATE_INBYTES];
        state_2d = new byte[D][D];
    }

    @Override
    public String getAlgorithmName()
    {
        return "Photon-Beetle Hash";
    }

    @Override
    public int getDigestSize()
    {
        return TAG_INBYTES;
    }

    @Override
    public void update(byte input)
    {
        buffer.write(input);
    }

    @Override
    public void update(byte[] input, int inOff, int len)
    {
        if ((inOff + len) > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        buffer.write(input, inOff, len);
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        if (32 + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        byte[] input = buffer.toByteArray();
        int inlen = input.length;
        if (inlen == 0)
        {
            state[STATE_INBYTES - 1] ^= 1 << LAST_THREE_BITS_OFFSET;
        }
        else if (inlen <= INITIAL_RATE_INBYTES)
        {
            System.arraycopy(input, 0, state, 0, inlen);
            if (inlen < INITIAL_RATE_INBYTES)
            {
                state[inlen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= (inlen < INITIAL_RATE_INBYTES ? (byte)1 : (byte)2) << LAST_THREE_BITS_OFFSET;
        }
        else
        {
            System.arraycopy(input, 0, state, 0, INITIAL_RATE_INBYTES);
            inlen -= INITIAL_RATE_INBYTES;
            int Dlen_inblocks = (inlen + RATE_INBYTES - 1) / RATE_INBYTES;
            int i, LastDBlocklen;
            for (i = 0; i < Dlen_inblocks - 1; i++)
            {
                PHOTON_Permutation();
                XOR(input, INITIAL_RATE_INBYTES + i * RATE_INBYTES, RATE_INBYTES);
            }
            PHOTON_Permutation();
            LastDBlocklen = inlen - i * RATE_INBYTES;
            XOR(input, INITIAL_RATE_INBYTES + i * RATE_INBYTES, LastDBlocklen);
            if (LastDBlocklen < RATE_INBYTES)
            {
                state[LastDBlocklen] ^= 0x01; // ozs
            }
            state[STATE_INBYTES - 1] ^= (inlen % RATE_INBYTES == 0 ? (byte)1 : (byte)2) << LAST_THREE_BITS_OFFSET;
        }
        PHOTON_Permutation();
        System.arraycopy(state, 0, output, outOff, SQUEEZE_RATE_INBYTES);
        PHOTON_Permutation();
        System.arraycopy(state, 0, output, outOff + SQUEEZE_RATE_INBYTES, TAG_INBYTES - SQUEEZE_RATE_INBYTES);
        return TAG_INBYTES;
    }

    void XOR(byte[] in_right, int rOff, int iolen_inbytes)
    {
        for (int i = 0; i < iolen_inbytes; i++)
        {
            state[i] ^= in_right[i + rOff];
        }
    }

    @Override
    public void reset()
    {
        buffer.reset();
        Arrays.fill(state, (byte)0);
    }

    void PHOTON_Permutation()
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
}
