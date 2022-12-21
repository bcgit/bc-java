package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
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

    enum MODE
    {
        ModeHash,
        ModeKeyed
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        /**
         * Xoodyak encryption and decryption is completely symmetrical, so the 'forEncryption' is irrelevant.
         */
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
        reset();
    }

    @Override
    public String getAlgorithmName()
    {
        return "Xoodak AEAD";
    }

    @Override
    public void processAADByte(byte input)
    {
        AbsorbAny(new byte[]{input}, 0, 1, Rabsorb, 0x03);
    }

    @Override
    public void processAADBytes(byte[] input, int inOff, int len)
    {
        AbsorbAny(input, inOff, len, Rabsorb, 0x03);
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
        if (mode != MODE.ModeKeyed)
        {
            throw new IllegalArgumentException("Xoodyak has not been initialised");
        }
        else if (aadFinished)
        {
            throw new IllegalArgumentException("Encryption must be done before associated data is processed");
        }
        int IOLen = output.length;
        int splitLen;
        byte[] P = new byte[Rkout];
        int Cu = 0x80;
        do
        {
            splitLen = Math.min(IOLen, Rkout); /* use Rkout instead of Rsqueeze, this function is only called in keyed mode */
            System.arraycopy(input, inOff, P, 0, splitLen);
            Up(null, 0, 0, Cu); /* Up without extract */
            /* Extract from Up and Add */
            for (int i = 0; i < splitLen; i++)
            {
                output[inOff++] = (byte)(input[outOff++] ^ state[i]);
            }
            Down(P, 0, splitLen, 0x00);
            Cu = 0x00;
            IOLen -= splitLen;
        }
        while (IOLen != 0);
        return 0;
    }

    @Override
    public int doFinal(byte[] output, int outOff)
        throws IllegalStateException, InvalidCipherTextException
    {
        getMac();
        System.arraycopy(tag, 0, output, outOff, TAGLEN);
        return TAGLEN;
    }

    @Override
    public byte[] getMac()
    {
        if (aadFinished)
        {
            return tag;
        }
        else
        {
            Up(tag, 0, TAGLEN, 0x40);
            aadFinished = true;
        }

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
        Arrays.fill(state, (byte)0);
        aadFinished = false;
        phase = PhaseUp;
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
                Up(null, 0, 0, 0);
            }
            splitLen = Math.min(XLen, r);
            Down(X, Xoff, splitLen, Cd);
            Cd = 0;
            Xoff += splitLen;
            XLen -= splitLen;
        }
        while (XLen != 0);
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
            System.arraycopy(state, YiOff, Yi, 0, YiLen);
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
