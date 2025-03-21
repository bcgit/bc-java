package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Ascon-AEAD128 was introduced as part of the NIST Lightweight Cryptography
 * competition and described in the NIST Special Publication SP 800-232 (Initial
 * Public Draft).
 * For additional details, see:
 * <ul>
 *     <li><a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a></li>
 *     <li><a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
 *     ASM implementations of Ascon (NIST SP 800-232)</a></li>
 * </ul>
 *
 * @version 1.3
 */
public class AsconAEAD128
    extends AsconBaseEngine
{
    public AsconAEAD128()
    {
        KEY_SIZE = IV_SIZE = MAC_SIZE = AADBufferSize = BlockSize = 16;
        ASCON_IV = 0x00001000808c0001L;
        algorithmName = "Ascon-AEAD128";
        nr = 8;
        dsep = -9223372036854775808L; //0x80L << 56
        setInnerMembers(ProcessingBufferType.Immediate, AADOperatorType.Default, DataOperatorType.Default);
    }

    protected long pad(int i)
    {
        return 0x01L << (i << 3);
    }

    @Override
    protected long loadBytes(byte[] in, int inOff)
    {
        return Pack.littleEndianToLong(in, inOff);
    }

    @Override
    protected void setBytes(long n, byte[] bs, int off)
    {
        Pack.longToLittleEndian(n, bs, off);
    }

    protected void ascon_aeadinit()
    {
        /* initialize */
        p.set(ASCON_IV, K0, K1, N0, N1);
        p.p(12);
        p.x3 ^= K0;
        p.x4 ^= K1;
    }

    protected void processFinalAAD()
    {
        if (m_aadPos == BlockSize)
        {
            p.x0 ^= loadBytes(m_aad, 0);
            p.x1 ^= loadBytes(m_aad, 8);
            m_aadPos -= BlockSize;
            p.p(nr);
        }
        Arrays.fill(m_aad, m_aadPos, AADBufferSize, (byte)0);
        if (m_aadPos >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            p.x0 ^= Pack.littleEndianToLong(m_aad, 0);
            p.x1 ^= Pack.littleEndianToLong(m_aad, 8) ^ pad(m_aadPos);
        }
        else
        {
            p.x0 ^= Pack.littleEndianToLong(m_aad, 0) ^ pad(m_aadPos);
        }
    }

    protected void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            long c0 = Pack.littleEndianToLong(input, 0);
            inLen -= 8;
            long c1 = Pack.littleEndianToLong(input, 8, inLen);
            Pack.longToLittleEndian(p.x0 ^ c0, output, outOff);
            Pack.longToLittleEndian(p.x1 ^ c1, output, outOff + 8, inLen);
            p.x0 = c0;
            p.x1 &= -(1L << (inLen << 3));
            p.x1 |= c1;
            p.x1 ^= pad(inLen);
        }
        else
        {
            if (inLen != 0)
            {
                long c0 = Pack.littleEndianToLong(input, 0, inLen);
                Pack.longToLittleEndian(p.x0 ^ c0, output, outOff, inLen);
                p.x0 &= -(1L << (inLen << 3));
                p.x0 |= c0;
            }
            p.x0 ^= pad(inLen);
        }
        finishData(State.DecFinal);
    }

    protected void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            p.x0 ^= Pack.littleEndianToLong(input, 0);
            inLen -= 8;
            p.x1 ^= Pack.littleEndianToLong(input, 8, inLen);
            Pack.longToLittleEndian(p.x0, output, outOff);
            Pack.longToLittleEndian(p.x1, output, outOff + 8);
            p.x1 ^= pad(inLen);
        }
        else
        {
            if (inLen != 0)
            {
                p.x0 ^= Pack.littleEndianToLong(input, 0, inLen);
                Pack.longToLittleEndian(p.x0, output, outOff, inLen);
            }
            p.x0 ^= pad(inLen);
        }
        finishData(State.EncFinal);
    }

    private void finishData(State nextState)
    {
        p.x2 ^= K0;
        p.x3 ^= K1;
        p.p(12);
        p.x3 ^= K0;
        p.x4 ^= K1;
        m_state = nextState;
    }

    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        K0 = Pack.littleEndianToLong(key, 0);
        K1 = Pack.littleEndianToLong(key, 8);
        N0 = Pack.littleEndianToLong(iv, 0);
        N1 = Pack.littleEndianToLong(iv, 8);
    }

    public String getAlgorithmVersion()
    {
        return "v1.3";
    }
}