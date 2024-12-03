package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Pack;

/**
 * Ascon-Hash256 was introduced in NIST Special Publication (SP) 800-232
 * (Initial Public Draft).
 * <p>
 * Additional details and the specification can be found in:
 * <a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a>.
 * For reference source code and implementation details, please see:
 * <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
 *  ASM implementations of Ascon (NIST SP 800-232)</a>.
 * </p>
 */
public class AsconHash256
    extends AsconBaseDigest
{
    public AsconHash256()
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
        return "Ascon-Hash256";
    }



    @Override
    public void reset()
    {
        super.reset();
        /* initialize */
        x0 = -7269279749984954751L;
        x1 = 5459383224871899602L;
        x2 = -5880230600644446182L;
        x3 = 4359436768738168243L;
        x4 = 1899470422303676269L;
    }
}
