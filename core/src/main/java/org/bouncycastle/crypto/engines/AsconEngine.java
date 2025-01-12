package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Pack;

/**
 * The {@code AsconEngine} class provides an implementation of ASCON AEAD version 1.2,
 * based on the official specification available at:
 * <a href="https://ascon.iaik.tugraz.at/">https://ascon.iaik.tugraz.at/</a> and the
 * updated specification document from the NIST competition:
 * <a href="https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf">
 * ASCON Specification (Finalist Round)
 * </a>.
 * <p>
 * This version references the C reference implementation provided by NIST, available at:
 * <a href="https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/ascon.zip">
 * ASCON C Reference Implementation (NIST Round 2)
 * </a>.
 * </p>
 * @deprecated Now superseded. Please refer to {@code AsconAEAD128Engine} for future implementations.
 */

public class AsconEngine
    extends AsconBaseEngine
{
    public enum AsconParameters
    {
        ascon80pq,
        ascon128a,
        ascon128
    }

    private final AsconParameters asconParameters;
    private long K2;

    public AsconEngine(AsconParameters asconParameters)
    {
        this.asconParameters = asconParameters;
        IV_SIZE = 16;
        MAC_SIZE = 16;
        switch (asconParameters)
        {
        case ascon80pq:
            KEY_SIZE = 20;
            ASCON_AEAD_RATE = 8;
            ASCON_IV = 0xa0400c0600000000L;
            algorithmName = "Ascon-80pq AEAD";
            break;
        case ascon128a:
            KEY_SIZE = 16;
            ASCON_AEAD_RATE = 16;
            ASCON_IV = 0x80800c0800000000L;
            algorithmName = "Ascon-128a AEAD";
            break;
        case ascon128:
            KEY_SIZE = 16;
            ASCON_AEAD_RATE = 8;
            ASCON_IV = 0x80400c0600000000L;
            algorithmName = "Ascon-128 AEAD";
            break;
        default:
            throw new IllegalArgumentException("invalid parameter setting for ASCON AEAD");
        }
        nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
        m_bufferSizeDecrypt = ASCON_AEAD_RATE + MAC_SIZE;
        m_buf = new byte[m_bufferSizeDecrypt];
        dsep = 1L;
    }

    protected long pad(int i)
    {
        return 0x80L << (56 - (i << 3));
    }

    @Override
    protected long loadBytes(byte[] in, int inOff)
    {
        return Pack.bigEndianToLong(in, inOff);
    }

    @Override
    protected void setBytes(long n, byte[] bs, int off)
    {
        Pack.longToBigEndian(n, bs, off);
    }
    protected void ascon_aeadinit()
    {
        /* initialize */
        x0 = ASCON_IV;
        if (KEY_SIZE == 20)
        {
            x0 ^= K0;
        }
        x1 = K1;
        x2 = K2;
        x3 = N0;
        x4 = N1;
        p(12);
        if (KEY_SIZE == 20)
        {
            x2 ^= K0;
        }
        x3 ^= K1;
        x4 ^= K2;
    }

    protected void processFinalAadBlock()
    {
        m_buf[m_bufPos] = (byte)0x80;
        if (m_bufPos >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            x0 ^= Pack.bigEndianToLong(m_buf, 0);
            x1 ^= Pack.bigEndianToLong(m_buf, 8) & (-1L << (56 - ((m_bufPos - 8) << 3)));
        }
        else
        {
            x0 ^= Pack.bigEndianToLong(m_buf, 0) & (-1L << (56 - (m_bufPos << 3)));
        }
    }

    protected void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            long c0 = Pack.bigEndianToLong(input, 0);
            x0 ^= c0;
            Pack.longToBigEndian(x0, output, outOff);
            x0 = c0;

            outOff += 8;
            inLen -= 8;
            x1 ^= pad(inLen);
            if (inLen != 0)
            {
                long c1 = Pack.littleEndianToLong_High(input, 8, inLen);
                x1 ^= c1;
                Pack.longToLittleEndian_High(x1, output, outOff, inLen);
                x1 &= -1L >>> (inLen << 3);
                x1 ^= c1;
            }
        }
        else
        {
            x0 ^= pad(inLen);
            if (inLen != 0)
            {
                long c0 = Pack.littleEndianToLong_High(input, 0, inLen);
                x0 ^= c0;
                Pack.longToLittleEndian_High(x0, output, outOff, inLen);
                x0 &= -1L >>> (inLen << 3);
                x0 ^= c0;
            }
        }

        finishData(State.DecFinal);
    }

    protected void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            x0 ^= Pack.bigEndianToLong(input, 0);
            Pack.longToBigEndian(x0, output, outOff);
            outOff += 8;
            inLen -= 8;
            x1 ^= pad(inLen);
            if (inLen != 0)
            {
                x1 ^= Pack.littleEndianToLong_High(input, 8, inLen);
                Pack.longToLittleEndian_High(x1, output, outOff, inLen);
            }
        }
        else
        {
            x0 ^= pad(inLen);
            if (inLen != 0)
            {
                x0 ^= Pack.littleEndianToLong_High(input, 0, inLen);
                Pack.longToLittleEndian_High(x0, output, outOff, inLen);
            }
        }
        finishData(State.EncFinal);
    }

    private void finishData(State nextState)
    {
        switch (asconParameters)
        {
        case ascon128:
            x1 ^= K1;
            x2 ^= K2;
            break;
        case ascon128a:
            x2 ^= K1;
            x3 ^= K2;
            break;
        case ascon80pq:
            x1 ^= (K0 << 32 | K1 >> 32);
            x2 ^= (K1 << 32 | K2 >> 32);
            x3 ^= K2 << 32;
            break;
        default:
            throw new IllegalStateException();
        }
        p(12);
        x3 ^= K1;
        x4 ^= K2;

        m_state = nextState;
    }

    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {

        N0 = Pack.bigEndianToLong(iv, 0);
        N1 = Pack.bigEndianToLong(iv, 8);
        if (KEY_SIZE == 16)
        {
            K1 = Pack.bigEndianToLong(key, 0);
            K2 = Pack.bigEndianToLong(key, 8);
        }
        else if (KEY_SIZE == 20)
        {
            K0 = Pack.bigEndianToInt(key, 0);
            K1 = Pack.bigEndianToLong(key, 4);
            K2 = Pack.bigEndianToLong(key, 12);
        }
        else
        {
            throw new IllegalStateException();
        }

        m_state = forEncryption ? State.EncInit : State.DecInit;

        reset(true);
    }

    public String getAlgorithmVersion()
    {
        return "v1.2";
    }
}
