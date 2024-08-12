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
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/**
 * Xoodyak v1, https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/xoodyak-spec-final.pdf
 * <p>
 * Xoodyak with reference to C Reference Impl from: https://github.com/XKCP/XKCP
 * </p>
 */

public class XoodyakEngine
    implements AEADCipher
{
    private boolean forEncryption;
    private byte[] state;
    private int phase;
    private MODE mode;
    private int Rabsorb;
    private final int f_bPrime = 48;
    private final int Rkout = 24;
    private byte[] K;
    private byte[] iv;
    private final int PhaseDown = 1;
    private final int PhaseUp = 2;
//    private final int NLANES = 12;
//    private final int NROWS = 3;
//    private final int NCOLUMS = 4;
    private final int MAXROUNDS = 12;
    private final int TAGLEN = 16;
    final int Rkin = 44;
    private byte[] tag;
    private final int[] RC = {0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060,
        0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012};
    private boolean aadFinished;
    private boolean encrypted;
    private boolean initialised = false;
    private final ByteArrayOutputStream aadData = new ByteArrayOutputStream();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();

    enum MODE
    {
        ModeHash,
        ModeKeyed
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;
        if (!(params instanceof ParametersWithIV))
        {
            throw new IllegalArgumentException("Xoodyak init parameters must include an IV");
        }
        ParametersWithIV ivParams = (ParametersWithIV)params;
        iv = ivParams.getIV();
        if (iv == null || iv.length != 16)
        {
            throw new IllegalArgumentException("Xoodyak requires exactly 16 bytes of IV");
        }
        if (!(ivParams.getParameters() instanceof KeyParameter))
        {
            throw new IllegalArgumentException("Xoodyak init parameters must include a key");
        }
        KeyParameter key = (KeyParameter)ivParams.getParameters();
        K = key.getKey();
        if (K.length != 16)
        {
            throw new IllegalArgumentException("Xoodyak key must be 128 bits long");
        }
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        state = new byte[48];
        tag = new byte[TAGLEN];
        initialised = true;
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Xoodyak AEAD";
    }

    @Override
    public void processAADByte(byte input)
    {
        if (aadFinished)
        {
            throw new IllegalArgumentException("AAD cannot be added after reading a full block(" + getBlockSize() +
                " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
        }
        aadData.write(input);
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        if (aadFinished)
        {
            throw new IllegalArgumentException("AAD cannot be added after reading a full block(" + getBlockSize() +
                " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
        }
        if ((inOff + len) > input.length)
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

    private void processAAD()
    {
        if (!aadFinished)
        {
            byte[] ad = aadData.toByteArray();
            AbsorbAny(ad, 0, ad.length, Rabsorb, 0x03);
            aadFinished = true;
        }
    }

    @Override
    public int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        throws DataLengthException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        if (mode != MODE.ModeKeyed)
        {
            throw new IllegalArgumentException("Xoodyak has not been initialised");
        }
        if (inOff + len > input.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        message.write(input, inOff, len);
        int blockLen = message.size() - (forEncryption ? 0 : TAGLEN);
        if (blockLen >= getBlockSize())
        {
            byte[] blocks = message.toByteArray();
            len = blockLen / getBlockSize() * getBlockSize();
            if (len + outOff > output.length)
            {
                throw new OutputLengthException("output buffer is too short");
            }
            processAAD();
            encrypt(blocks, 0, len, output, outOff);
            message.reset();
            message.write(blocks, len, blocks.length - len);
            return len;
        }
        return 0;
    }

    private int encrypt(byte[] input, int inOff, int len, byte[] output, int outOff)
    {
        int IOLen = len;
        int splitLen;
        byte[] P = new byte[Rkout];
        int Cu = encrypted ? 0 : 0x80;
        while (IOLen != 0 || !encrypted)
        {
            splitLen = Math.min(IOLen, Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
            if (forEncryption)
            {
                System.arraycopy(input, inOff, P, 0, splitLen);
            }
            Up(null, 0, Cu); /* Up without extract */
            /* Extract from Up and Add */
            for (int i = 0; i < splitLen; i++)
            {
                output[outOff + i] = (byte)(input[inOff++] ^ state[i]);
            }
            if (forEncryption)
            {
                Down(P, 0, splitLen, 0x00);
            }
            else
            {
                Down(output, outOff, splitLen, 0x00);
            }
            Cu = 0x00;
            outOff += splitLen;
            IOLen -= splitLen;
            encrypted = true;
        }
        return len;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        if (!initialised)
        {
            throw new IllegalArgumentException("Need call init function before encryption/decryption");
        }
        byte[] blocks = message.toByteArray();
        int len = message.size();
        if ((forEncryption && len + TAGLEN + outOff > output.length) || (!forEncryption && len - TAGLEN + outOff > output.length))
        {
            throw new OutputLengthException("output buffer too short");
        }
        processAAD();
        int rv = 0;
        if (forEncryption)
        {
            encrypt(blocks, 0, len, output, outOff);
            outOff += len;
            tag = new byte[TAGLEN];
            Up(tag, TAGLEN, 0x40);
            System.arraycopy(tag, 0, output, outOff, TAGLEN);
            rv = len + TAGLEN;
        }
        else
        {
            int inOff = len - TAGLEN;
            rv = inOff;
            encrypt(blocks, 0, inOff, output, outOff);
            tag = new byte[TAGLEN];
            Up(tag, TAGLEN, 0x40);
            for (int i = 0; i < TAGLEN; ++i)
            {
                if (tag[i] != blocks[inOff++])
                {
                    throw new IllegalArgumentException("Mac does not match");
                }
            }
        }
        reset(false);
        return rv;
    }

    @Override
    public byte[] getMac()
    {
        return tag;
    }

    @Override
    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    @Override
    public int getOutputSize(int len)
    {
        return len + TAGLEN;
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
            tag = null;
        }
        Arrays.fill(state, (byte)0);
        aadFinished = false;
        encrypted = false;
        phase = PhaseUp;
        message.reset();
        aadData.reset();
        //Absorb key
        int KLen = K.length;
        int IDLen = iv.length;
        byte[] KID = new byte[Rkin];
        mode = MODE.ModeKeyed;
        Rabsorb = Rkin;
        System.arraycopy(K, 0, KID, 0, KLen);
        System.arraycopy(iv, 0, KID, KLen, IDLen);
        KID[KLen + IDLen] = (byte)IDLen;
        AbsorbAny(KID, 0, KLen + IDLen + 1, Rabsorb, 0x02);
    }

    private void AbsorbAny(byte[] X, int Xoff, int XLen, int r, int Cd)
    {
        int splitLen;
        do
        {
            if (phase != PhaseUp)
            {
                Up(null, 0, 0);
            }
            splitLen = Math.min(XLen, r);
            Down(X, Xoff, splitLen, Cd);
            Cd = 0;
            Xoff += splitLen;
            XLen -= splitLen;
        }
        while (XLen != 0);
    }

    private void Up(byte[] Yi, int YiLen, int Cu)
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
            System.arraycopy(state, 0, Yi, 0, YiLen);
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

    public int getBlockSize()
    {
        return Rkout;
    }

    public int getKeyBytesSize()
    {
        return 16;
    }

    public int getIVBytesSize()
    {
        return 16;
    }
}
