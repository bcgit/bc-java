package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Pack;

/**
 * Ascon-XOF128 was introduced in NIST Special Publication (SP) 800-232
 * (Initial Public Draft).
 * <p>
 * Additional details and the specification can be found in:
 * <a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a>.
 * For reference source code and implementation details, please see:
 * <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
 *  ASM implementations of Ascon (NIST SP 800-232)</a>.
 * </p>
 */
public class AsconXof128
    extends AsconBaseDigest
    implements Xof
{
    public AsconXof128()
    {
        reset();
    }

    protected long pad(int i)
    {
        return 0x01L << (i << 3);
    }

    protected long loadBytes(final byte[] bytes, int inOff, int n)
    {
        return Pack.littleEndianToLong(bytes, inOff, n);
    }

    protected void setBytes(long w, byte[] bytes, int inOff, int n)
    {
        Pack.longToLittleEndian(w, bytes, inOff, n);
    }

    @Override
    public String getAlgorithmName()
    {
        return "Ascon-XOF-128";
    }

    @Override
    public int doOutput(byte[] output, int outOff, int outLen)
    {
        return hash(output, outOff, outLen);
    }

    @Override
    public int doFinal(byte[] output, int outOff)
    {
        return doOutput(output, outOff, getDigestSize());
    }

    @Override
    public int doFinal(byte[] output, int outOff, int outLen)
    {
        return doOutput(output, outOff, outLen);
    }

    @Override
    public int getByteLength()
    {
        return 8;
    }

    @Override
    public void reset()
    {
        buffer.reset();
        /* initialize */
        x0 = -2701369817892108309L;
        x1 = -3711838248891385495L;
        x2 = -1778763697082575311L;
        x3 = 1072114354614917324L;
        x4 = -2282070310009238562L;
    }
}

