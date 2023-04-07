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
    private final int NLANES = 12;
    private final int NROWS = 3;
    private final int NCOLUMS = 4;
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

    private int index(int x, int y)
    {
        return (((y % NROWS) * NCOLUMS) + ((x) % NCOLUMS));
    }

    private int ROTL32(int a, int offset)
    {
        return (a << (offset & 31)) ^ (a >>> ((32 - (offset)) & 31));
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
