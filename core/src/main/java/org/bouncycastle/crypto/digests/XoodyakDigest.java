package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Xoodyak v1, https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
 * <p>
 * Xoodyak with reference to C Reference Impl from: https://github.com/XKCP/XKCP
 * </p>
 */

public class XoodyakDigest
    implements Digest
{
    private byte[] state;
    private int phase;
    private MODE mode;
    private int Rabsorb;
    private final int f_bPrime = 48;
    private final int Rhash = 16;
    private final int PhaseDown = 1;
    private final int PhaseUp = 2;
    private final int NLANES = 12;
    private final int NROWS = 3;
    private final int NCOLUMS = 4;
    private final int MAXROUNDS = 12;
    private final int TAGLEN = 16;
    private final int[] RC = {0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060,
        0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012};
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    enum MODE
    {
        ModeHash,
        ModeKeyed
    }

    public XoodyakDigest()
    {
        state = new byte[48];
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Xoodyak Hash";
    }

    @Override
    public int getDigestSize()
    {
        return 32;
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
        int inOff = 0;
        int len = buffer.size();
        int Cd = 0x03;
        int splitLen;
        do
        {
            if (phase != PhaseUp)
            {
                Up(null, 0, 0, 0);
            }
            splitLen = Math.min(len, Rabsorb);
            Down(input, inOff, splitLen, Cd);
            Cd = 0;
            inOff += splitLen;
            len -= splitLen;
        }
        while (len != 0);
        Up(output, outOff, TAGLEN, 0x40);
        Down(null, 0, 0, 0);
        Up(output, outOff + TAGLEN, TAGLEN, 0);
        return 32;
    }

    @Override
    public void reset()
    {
        Arrays.fill(state, (byte)0);
        phase = PhaseUp;
        mode = MODE.ModeHash;
        Rabsorb = Rhash;
        buffer.reset();
    }

    private void Up(byte[] Yi, int YiOff, int YiLen, int Cu)
    {
        if (mode != MODE.ModeHash)
        {
            state[f_bPrime - 1] ^= Cu;
        }
        int[] a = new int[NLANES];
        Pack.littleEndianToInt(state, 0, a, 0, a.length);
        int x, y;
        int[] b = new int[NLANES];
        int[] p = new int[NCOLUMS];
        int[] e = new int[NCOLUMS];
        for (int i = 0; i < MAXROUNDS; ++i)
        {
            /* Theta: Column Parity Mixer */
            for (x = 0; x < NCOLUMS; ++x)
            {
                p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
            }
            for (x = 0; x < NCOLUMS; ++x)
            {
                y = p[(x + 3) & 3];
                e[x] = ROTL32(y, 5) ^ ROTL32(y, 14);
            }
            for (x = 0; x < NCOLUMS; ++x)
            {
                for (y = 0; y < NROWS; ++y)
                {
                    a[index(x, y)] ^= e[x];
                }
            }
            /* Rho-west: plane shift */
            for (x = 0; x < NCOLUMS; ++x)
            {
                b[index(x, 0)] = a[index(x, 0)];
                b[index(x, 1)] = a[index(x + 3, 1)];
                b[index(x, 2)] = ROTL32(a[index(x, 2)], 11);
            }
            /* Iota: round ant */
            b[0] ^= RC[i];
            /* Chi: non linear layer */
            for (x = 0; x < NCOLUMS; ++x)
            {
                for (y = 0; y < NROWS; ++y)
                {
                    a[index(x, y)] = b[index(x, y)] ^ (~b[index(x, y + 1)] & b[index(x, y + 2)]);
                }
            }
            /* Rho-east: plane shift */
            for (x = 0; x < NCOLUMS; ++x)
            {
                b[index(x, 0)] = a[index(x, 0)];
                b[index(x, 1)] = ROTL32(a[index(x, 1)], 1);
                b[index(x, 2)] = ROTL32(a[index(x + 2, 2)], 8);
            }
            System.arraycopy(b, 0, a, 0, NLANES);
        }
        Pack.intToLittleEndian(a, 0, a.length, state, 0);
        phase = PhaseUp;
        if (Yi != null)
        {
            System.arraycopy(state, 0, Yi, YiOff, YiLen);
        }
    }

    void Down(byte[] Xi, int XiOff, int XiLen, int Cd)
    {
        for (int i = 0; i < XiLen; i++)
        {
            state[i] ^= Xi[XiOff++];
        }
        state[XiLen] ^= 0x01;
        state[f_bPrime - 1] ^= (mode == MODE.ModeHash) ? (Cd & 0x01) : Cd;
        phase = PhaseDown;
    }

    private int index(int x, int y)
    {
        return (((y % NROWS) * NCOLUMS) + ((x) % NCOLUMS));
    }

    private int ROTL32(int a, int offset)
    {
        return (a << (offset & 31)) ^ (a >>> ((32 - (offset)) & 31));
    }

}
