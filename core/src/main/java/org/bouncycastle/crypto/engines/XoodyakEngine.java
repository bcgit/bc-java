package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.digests.XoodyakDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Xoodyak v1, <a href="https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf"></a>
 * <p>
 * Xoodyak with reference to C Reference Impl from: <a href="https://github.com/XKCP/XKCP"></a>
 * </p>
 */

public class XoodyakEngine
    extends AEADBaseEngine
{
    private final byte[] state;
    private int phase;
    private int mode;
    private static final int f_bPrime_1 = 47;
    private byte[] K;
    private byte[] iv;
    private static final int PhaseUp = 2;
    private static final int PhaseDown = 1;
    private static final int[] RC = {0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060,
        0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012};
    private boolean encrypted;
    private byte aadcd;
    private static final int ModeKeyed = 0;
    private static final int ModeHash = 1;

    public XoodyakEngine()
    {
        algorithmName = "Xoodyak AEAD";
        KEY_SIZE = IV_SIZE = MAC_SIZE = 16;
        BlockSize = 24;
        AADBufferSize = 44;
        state = new byte[48];
        setInnerMembers(ProcessingBufferType.Immediate, AADOperatorType.Default, DataOperatorType.Counter);
    }

    @Override
    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        K = key;
        this.iv = iv;
    }

    protected void processBufferAAD(byte[] input, int inOff)
    {
        AbsorbAny(input, inOff, AADBufferSize, aadcd);
        aadcd = 0;
    }

    protected void processFinalAAD()
    {
        AbsorbAny(m_aad, 0, m_aadPos, aadcd);
    }

    @Override
    protected void finishAAD(State nextState, boolean isDoFinal)
    {
        finishAAD3(nextState, isDoFinal);
    }

    protected void processBufferEncrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        up(mode, state, encrypted ? 0 : 0x80); /* Up without extract */
        /* Extract from Up and Add */
        Bytes.xor(BlockSize, state, input, inOff, output, outOff);
        down(mode, state, input, inOff, BlockSize, 0x00);
        phase = PhaseDown;
        encrypted = true;
    }

    protected void processBufferDecrypt(byte[] input, int inOff, byte[] output, int outOff)
    {
        up(mode, state, encrypted ? 0 : 0x80); /* Up without extract */
        /* Extract from Up and Add */
        Bytes.xor(BlockSize, state, input, inOff, output, outOff);
        down(mode, state, output, outOff, BlockSize, 0x00);
        phase = PhaseDown;
        encrypted = true;
    }

    @Override
    protected void processFinalBlock(byte[] output, int outOff)
    {
        if (m_bufPos != 0 || !encrypted)
        {
            up(mode, state, encrypted ? 0 : 0x80); /* Up without extract */
            /* Extract from Up and Add */
            Bytes.xor(m_bufPos, state, m_buf, 0, output, outOff);
            if (forEncryption)
            {
                down(mode, state, m_buf, 0, m_bufPos, 0x00);
            }
            else
            {
                down(mode, state, output, outOff, m_bufPos, 0x00);
            }
            phase = PhaseDown;
        }
        up(mode, state, 0x40);
        System.arraycopy(state, 0, mac, 0, MAC_SIZE);
        phase = PhaseUp;
    }

    protected void reset(boolean clearMac)
    {
        super.reset(clearMac);
        Arrays.fill(state, (byte)0);
        encrypted = false;
        phase = PhaseUp;
        aadcd = (byte)0x03;
        //Absorb key
        int KLen = K.length;
        int IDLen = iv.length;
        byte[] KID = new byte[AADBufferSize];
        mode = ModeKeyed;
        System.arraycopy(K, 0, KID, 0, KLen);
        System.arraycopy(iv, 0, KID, KLen, IDLen);
        KID[KLen + IDLen] = (byte)IDLen;
        AbsorbAny(KID, 0, KLen + IDLen + 1, 0x02);
    }

    private void AbsorbAny(byte[] X, int Xoff, int XLen, int Cd)
    {
        int splitLen;
        if (phase != PhaseUp)
        {
            up(mode, state, 0);
        }
        do
        {
            splitLen = Math.min(XLen, AADBufferSize);
            down(mode, state, X, Xoff, splitLen, Cd);
            phase = PhaseDown;
            Cd = 0;
            Xoff += splitLen;
            XLen -= splitLen;
        }
        while (XLen != 0);
    }

    public static void up(XoodyakDigest.Friend friend, int mode, byte[] state, int Cu)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by XoodyakDigest");
        }
        up(mode, state, Cu);
    }

    private static void up(int mode, byte[] state, int Cu)
    {
        if (mode != ModeHash)
        {
            state[f_bPrime_1] ^= Cu;
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

        for (int i = 0; i < 12; ++i)
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

            /* Chi: non-linear layer */
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
    }

    public static void down(XoodyakDigest.Friend friend, int mode, byte[] state, byte[] Xi, int XiOff, int XiLen, int Cd)
    {
        if (null == friend)
        {
            throw new NullPointerException("This method is only for use by XoodyakDigest");
        }
        down(mode, state, Xi, XiOff, XiLen, Cd);
    }

    private static void down(int mode, byte[] state, byte[] Xi, int XiOff, int XiLen, int Cd)
    {
        Bytes.xorTo(XiLen, Xi, XiOff, state);
        state[XiLen] ^= 0x01;
        state[f_bPrime_1] ^= (mode == ModeHash) ? (Cd & 0x01) : Cd;
    }
}
