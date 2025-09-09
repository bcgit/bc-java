package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Ascon-AEAD128 was introduced in NIST Special Publication (SP) 800-232
 * <p>
 * Additional details and the specification can be found in:
 * <a href="https://csrc.nist.gov/pubs/sp/800/232/final">NIST SP 800-232
 * Ascon-Based Lightweight Cryptography Standards for Constrained Devices</a>.
 * For reference source code and implementation details, please see:
 * <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
 * ASM implementations of Ascon (NIST SP 800-232)</a>.
 * </p>
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
        macSizeLowerBound = 4;
        setInnerMembers(ProcessingBufferType.Immediate, AADOperatorType.DataLimit, DataOperatorType.DataLimit);
        dataLimitCounter.init(54);
        decryptionFailureCounter = new DecryptionFailureCounter();
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
        int lambda = (MAC_SIZE << 3) - 32;
        long K0 = Pack.littleEndianToLong(key, 0);
        long K1 = Pack.littleEndianToLong(key, 8);
        decryptionFailureCounter.init(lambda);
        if (this.K0 != K0 || this.K1 != K1)
        {
            dataLimitCounter.reset();
            decryptionFailureCounter.reset();
            this.K0 = K0;
            this.K1 = K1;
        }
        N0 = Pack.littleEndianToLong(iv, 0);
        N1 = Pack.littleEndianToLong(iv, 8);
    }

    public String getAlgorithmVersion()
    {
        return "v1.3";
    }
}