package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Ascon-CXOF128 was introduced in NIST Special Publication (SP) 800-232
 * (Initial Public Draft).
 * <p>
 * Additional details and the specification can be found in:
 * <a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a>.
 * For reference source code and implementation details, please see:
 * <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
 * ASM implementations of Ascon (NIST SP 800-232)</a>.
 * </p>
 */
public class AsconCxof128
    extends AsconBaseDigest
    implements Xof
{
    private byte[] s;

    public AsconCxof128(byte[] s)
    {
        if (s.length > 2048)
        {
            throw new DataLengthException("customized string is too long");
        }
        this.s = Arrays.clone(s);
        reset();
    }

    public AsconCxof128(byte[] s, int off, int len)
    {
        if ((off + len) > s.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        if (len > 2048)
        {
            throw new DataLengthException("customized string is too long");
        }
        this.s = Arrays.copyOfRange(s, off, off + len);
        reset();
    }

    public AsconCxof128()
    {
        reset();
    }

    protected long pad(int i)
    {
        return 0x01L << (i << 3);
    }

    protected long loadBytes(final byte[] bytes, int inOff)
    {
        return Pack.littleEndianToLong(bytes, inOff);
    }

    protected long loadBytes(final byte[] bytes, int inOff, int n)
    {
        return Pack.littleEndianToLong(bytes, inOff, n);
    }

    protected void setBytes(long w, byte[] bytes, int inOff)
    {
        Pack.longToLittleEndian(w, bytes, inOff);
    }

    protected void setBytes(long w, byte[] bytes, int inOff, int n)
    {
        Pack.longToLittleEndian(w, bytes, inOff, n);
    }

    @Override
    public String getAlgorithmName()
    {
        return "Ascon-CXOF128";
    }

    @Override
    public int doOutput(byte[] output, int outOff, int outLen)
    {
        if (CRYPTO_BYTES + outOff > output.length)
        {
            throw new OutputLengthException("output buffer is too short");
        }
        finishAbsorbing();
        /* squeeze full output blocks */
        squeeze(output, outOff, outLen);
        return outLen;
    }


    @Override
    public int doFinal(byte[] output, int outOff, int outLen)
    {
        return doOutput(output, outOff, outLen);
    }

    @Override
    public void reset()
    {
        super.reset();
        /* initialize */
        x0 = 7445901275803737603L;
        x1 = 4886737088792722364L;
        x2 = -1616759365661982283L;
        x3 = 3076320316797452470L;
        x4 = -8124743304765850554L;
        if (s != null)
        {
            update(s, 0, s.length);
            finishAbsorbing();
        }
    }
}

