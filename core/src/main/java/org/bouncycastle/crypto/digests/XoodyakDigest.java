package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
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
//    private final int NLANES = 12;
//    private final int NROWS = 3;
//    private final int NCOLUMS = 4;
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
        reset();
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

        int a0 = Pack.littleEndianToInt(state, 0);
        int a1 = Pack.littleEndianToInt(state, 4);
        int a2 = Pack.littleEndianToInt(state, 8);
        int a3 = Pack.littleEndianToInt(state, 12);
        int a4 = Pack.littleEndianToInt(state, 16);
        int a5 = Pack.littleEndianToInt(state, 20);
        int a6 = Pack.littleEndianToInt(state, 24);
        int a7 = Pack.littleEndianToInt(state, 28);
        int a8 = Pack.littleEndianToInt(state, 32);
        int a9 = Pack.littleEndianToInt(state, 36);
        int a10 = Pack.littleEndianToInt(state, 40);
        int a11 = Pack.littleEndianToInt(state, 44);

        for (int i = 0; i < MAXROUNDS; ++i)
        {
            /* Theta: Column Parity Mixer */
            int p0 = a0 ^ a4 ^ a8;
            int p1 = a1 ^ a5 ^ a9;
            int p2 = a2 ^ a6 ^ a10;
            int p3 = a3 ^ a7 ^ a11;

            int e0 = Integers.rotateLeft(p3, 5) ^ Integers.rotateLeft(p3, 14);
            int e1 = Integers.rotateLeft(p0, 5) ^ Integers.rotateLeft(p0, 14);
            int e2 = Integers.rotateLeft(p1, 5) ^ Integers.rotateLeft(p1, 14);
            int e3 = Integers.rotateLeft(p2, 5) ^ Integers.rotateLeft(p2, 14);

            a0 ^= e0;
            a4 ^= e0;
            a8 ^= e0;

            a1 ^= e1;
            a5 ^= e1;
            a9 ^= e1;

            a2 ^= e2;
            a6 ^= e2;
            a10 ^= e2;

            a3 ^= e3;
            a7 ^= e3;
            a11 ^= e3;
            
            /* Rho-west: plane shift */
            int b0 = a0;
            int b1 = a1;
            int b2 = a2;
            int b3 = a3;

            int b4 = a7;
            int b5 = a4;
            int b6 = a5;
            int b7 = a6;

            int b8 = Integers.rotateLeft(a8, 11);
            int b9 = Integers.rotateLeft(a9, 11);
            int b10 = Integers.rotateLeft(a10, 11);
            int b11 = Integers.rotateLeft(a11, 11);

            /* Iota: round ant */
            b0 ^= RC[i];
            
            /* Chi: non linear layer */
            a0 = b0 ^ (~b4 & b8);
            a1 = b1 ^ (~b5 & b9);
            a2 = b2 ^ (~b6 & b10);
            a3 = b3 ^ (~b7 & b11);

            a4 = b4 ^ (~b8 & b0);
            a5 = b5 ^ (~b9 & b1);
            a6 = b6 ^ (~b10 & b2);
            a7 = b7 ^ (~b11 & b3);

            b8 ^= (~b0 & b4);
            b9 ^= (~b1 & b5);
            b10 ^= (~b2 & b6);
            b11 ^= (~b3 & b7);
            
            /* Rho-east: plane shift */
            a4 = Integers.rotateLeft(a4, 1);
            a5 = Integers.rotateLeft(a5, 1);
            a6 = Integers.rotateLeft(a6, 1);
            a7 = Integers.rotateLeft(a7, 1);

            a8 = Integers.rotateLeft(b10, 8);
            a9 = Integers.rotateLeft(b11, 8);
            a10 = Integers.rotateLeft(b8, 8);
            a11 = Integers.rotateLeft(b9, 8);
        }

        Pack.intToLittleEndian(a0, state, 0);
        Pack.intToLittleEndian(a1, state, 4);
        Pack.intToLittleEndian(a2, state, 8);
        Pack.intToLittleEndian(a3, state, 12);
        Pack.intToLittleEndian(a4, state, 16);
        Pack.intToLittleEndian(a5, state, 20);
        Pack.intToLittleEndian(a6, state, 24);
        Pack.intToLittleEndian(a7, state, 28);
        Pack.intToLittleEndian(a8, state, 32);
        Pack.intToLittleEndian(a9, state, 36);
        Pack.intToLittleEndian(a10, state, 40);
        Pack.intToLittleEndian(a11, state, 44);

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
}
