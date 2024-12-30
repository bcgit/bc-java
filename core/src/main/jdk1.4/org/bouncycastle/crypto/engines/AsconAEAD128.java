package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
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
        CRYPTO_KEYBYTES = 16;
        CRYPTO_ABYTES = 16;
        ASCON_AEAD_RATE = 16;
        ASCON_IV = 0x00001000808c0001L;
        algorithmName = "Ascon-AEAD128";
        nr = 8;
        m_bufferSizeDecrypt = ASCON_AEAD_RATE + CRYPTO_ABYTES;
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
        finishData(DecFinal);
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
        finishData(EncFinal);
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

    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        KeyParameter key;
        byte[] npub;
        if (params instanceof AEADParameters)
        {
            AEADParameters aeadParameters = (AEADParameters)params;
            key = aeadParameters.getKey();
            npub = aeadParameters.getNonce();
            initialAssociatedText = aeadParameters.getAssociatedText();

            int macSizeBits = aeadParameters.getMacSize();
            if (macSizeBits != CRYPTO_ABYTES * 8)
            {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
        }
        else if (params instanceof ParametersWithIV)
        {
            ParametersWithIV withIV = (ParametersWithIV)params;
            key = (KeyParameter)withIV.getParameters();
            npub = withIV.getIV();
            initialAssociatedText = null;
        }
        else
        {
            throw new IllegalArgumentException("invalid parameters passed to Ascon");
        }

        if (key == null)
        {
            throw new IllegalArgumentException("Ascon Init parameters must include a key");
        }
        if (npub == null || npub.length != CRYPTO_ABYTES)
        {
            throw new IllegalArgumentException("Ascon-AEAD-128 requires exactly " + CRYPTO_ABYTES + " bytes of IV");
        }

        byte[] k = key.getKey();
        if (k.length != CRYPTO_KEYBYTES)
        {
            throw new IllegalArgumentException("Ascon-AEAD-128 key must be " + CRYPTO_KEYBYTES + " bytes long");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(
            this.getAlgorithmName(), 128, params, Utils.getPurpose(forEncryption)));
        K0 = Pack.littleEndianToLong(k, 0);
        K1 = Pack.littleEndianToLong(k, 8);
        N0 = Pack.littleEndianToLong(npub, 0);
        N1 = Pack.littleEndianToLong(npub, 8);

        m_state = forEncryption ? EncInit : DecInit;

        reset(true);
    }

    public String getAlgorithmVersion()
    {
        return "v1.3";
    }
}

