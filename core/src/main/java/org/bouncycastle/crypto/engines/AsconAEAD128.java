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
        KEY_SIZE = 16;
        IV_SIZE = 16;
        MAC_SIZE = 16;
        ASCON_AEAD_RATE = 16;
        ASCON_IV = 0x00001000808c0001L;
        algorithmName = "Ascon-AEAD128";
        nr = 8;
        m_bufferSizeDecrypt = ASCON_AEAD_RATE + MAC_SIZE;
        m_buf = new byte[m_bufferSizeDecrypt];
        dsep = -9223372036854775808L; //0x80L << 56
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
        x0 = ASCON_IV;
        x1 = K0;
        x2 = K1;
        x3 = N0;
        x4 = N1;
        p(12);
        x3 ^= K0;
        x4 ^= K1;
    }

    protected void processFinalAadBlock()
    {
        Arrays.fill(m_buf, m_bufPos, m_buf.length, (byte) 0);
        if (m_bufPos >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            x0 ^= Pack.littleEndianToLong(m_buf, 0);
            x1 ^= Pack.littleEndianToLong(m_buf, 8) ^ pad(m_bufPos);
        }
        else
        {
            x0 ^= Pack.littleEndianToLong(m_buf, 0) ^ pad(m_bufPos);
        }
    }

    protected void processFinalDecrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            long c0 = Pack.littleEndianToLong(input, 0);
            inLen -= 8;
            long c1 = Pack.littleEndianToLong(input, 8, inLen);
            Pack.longToLittleEndian(x0 ^ c0, output, outOff);
            Pack.longToLittleEndian(x1 ^ c1, output, outOff + 8, inLen);
            x0 = c0;
            x1 &= -(1L << (inLen << 3));
            x1 |= c1;
            x1 ^= pad(inLen);
        }
        else
        {
            if (inLen != 0)
            {
                long c0 = Pack.littleEndianToLong(input, 0, inLen);
                Pack.longToLittleEndian(x0 ^ c0, output, outOff, inLen);
                x0 &= -(1L << (inLen << 3));
                x0 |= c0;
            }
            x0 ^= pad(inLen);
        }
        finishData(State.DecFinal);
    }

    protected void processFinalEncrypt(byte[] input, int inLen, byte[] output, int outOff)
    {
        if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
        {
            x0 ^= Pack.littleEndianToLong(input, 0);
            inLen -= 8;
            x1 ^= Pack.littleEndianToLong(input, 8, inLen);
            Pack.longToLittleEndian(x0, output, outOff);
            Pack.longToLittleEndian(x1, output, outOff + 8);
            x1 ^= pad(inLen);
        }
        else
        {
            if (inLen != 0)
            {
                x0 ^= Pack.littleEndianToLong(input, 0, inLen);
                Pack.longToLittleEndian(x0, output, outOff, inLen);
            }
            x0 ^= pad(inLen);
        }
        finishData(State.EncFinal);
    }

    private void finishData(State nextState)
    {
        x2 ^= K0;
        x3 ^= K1;
        p(12);
        x3 ^= K0;
        x4 ^= K1;
        m_state = nextState;
    }

    protected void init(byte[] key, byte[] iv)
        throws IllegalArgumentException
    {
        K0 = Pack.littleEndianToLong(key, 0);
        K1 = Pack.littleEndianToLong(key, 8);
        N0 = Pack.littleEndianToLong(iv, 0);
        N1 = Pack.littleEndianToLong(iv, 8);

        m_state = forEncryption ? State.EncInit : State.DecInit;

        reset(true);
    }

    public String getAlgorithmVersion()
    {
        return "v1.3";
    }
}

