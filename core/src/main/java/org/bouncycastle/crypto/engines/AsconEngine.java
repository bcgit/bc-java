package org.bouncycastle.crypto.engines;

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
 *
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
        IV_SIZE = MAC_SIZE = 16;
        switch (asconParameters)
        {
        case ascon80pq:
            KEY_SIZE = 20;
            BlockSize = 8;
            ASCON_IV = 0xa0400c0600000000L;
            algorithmName = "Ascon-80pq AEAD";
            break;
        case ascon128a:
            KEY_SIZE = 16;
            BlockSize = 16;
            ASCON_IV = 0x80800c0800000000L;
            algorithmName = "Ascon-128a AEAD";
            break;
        case ascon128:
            KEY_SIZE = 16;
            BlockSize = 8;
            ASCON_IV = 0x80400c0600000000L;
            algorithmName = "Ascon-128 AEAD";
            break;
        default:
            throw new IllegalArgumentException("invalid parameter setting for ASCON AEAD");
        }
        nr = (BlockSize == 8) ? 6 : 8;
        AADBufferSize = BlockSize;
        dsep = 1L;
        setInnerMembers(ProcessingBufferType.Immediate, AADOperatorType.Default, DataOperatorType.Default);
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
        p.set(ASCON_IV, K1, K2, N0, N1);
        if (KEY_SIZE == 20)
        {
            p.x0 ^= K0;
        }
        p.p(12);
        if (KEY_SIZE == 20)
        {
            p.x2 ^= K0;
        }
        p.x3 ^= K1;
        p.x4 ^= K2;
    }

    protected void processFinalAAD()
    {
        m_aad[m_aadPos] = (byte)0x80;
        if (m_aadPos >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            p.x0 ^= Pack.bigEndianToLong(m_aad, 0);
            p.x1 ^= Pack.bigEndianToLong(m_aad, 8) & (-1L << (56 - ((m_aadPos - 8) << 3)));
        }
        else
        {
            p.x0 ^= Pack.bigEndianToLong(m_aad, 0) & (-1L << (56 - (m_aadPos << 3)));
        }
    }

    protected void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            long c0 = Pack.bigEndianToLong(input, 0);
            p.x0 ^= c0;
            Pack.longToBigEndian(p.x0, output, outOff);
            p.x0 = c0;

            outOff += 8;
            inLen -= 8;
            p.x1 ^= pad(inLen);
            if (inLen != 0)
            {
                long c1 = Pack.littleEndianToLong_High(input, 8, inLen);
                p.x1 ^= c1;
                Pack.longToLittleEndian_High(p.x1, output, outOff, inLen);
                p.x1 &= -1L >>> (inLen << 3);
                p.x1 ^= c1;
            }
        }
        else
        {
            p.x0 ^= pad(inLen);
            if (inLen != 0)
            {
                long c0 = Pack.littleEndianToLong_High(input, 0, inLen);
                p.x0 ^= c0;
                Pack.longToLittleEndian_High(p.x0, output, outOff, inLen);
                p.x0 &= -1L >>> (inLen << 3);
                p.x0 ^= c0;
            }
        }

        finishData(State.DecFinal);
    }

    protected void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            p.x0 ^= Pack.bigEndianToLong(input, 0);
            Pack.longToBigEndian(p.x0, output, outOff);
            outOff += 8;
            inLen -= 8;
            p.x1 ^= pad(inLen);
            if (inLen != 0)
            {
                p.x1 ^= Pack.littleEndianToLong_High(input, 8, inLen);
                Pack.longToLittleEndian_High(p.x1, output, outOff, inLen);
            }
        }
        else
        {
            p.x0 ^= pad(inLen);
            if (inLen != 0)
            {
                p.x0 ^= Pack.littleEndianToLong_High(input, 0, inLen);
                Pack.longToLittleEndian_High(p.x0, output, outOff, inLen);
            }
        }
        finishData(State.EncFinal);
    }

    protected void finishData(State nextState)
    {
        switch (asconParameters)
        {
        case ascon128:
            p.x1 ^= K1;
            p.x2 ^= K2;
            break;
        case ascon128a:
            p.x2 ^= K1;
            p.x3 ^= K2;
            break;
        case ascon80pq:
            p.x1 ^= (K0 << 32 | K1 >> 32);
            p.x2 ^= (K1 << 32 | K2 >> 32);
            p.x3 ^= K2 << 32;
            break;
        default:
            throw new IllegalStateException();
        }
        p.p(12);
        p.x3 ^= K1;
        p.x4 ^= K2;

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
    }

    public String getAlgorithmVersion()
    {
        return "v1.2";
    }
}