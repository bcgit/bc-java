package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
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
public class AsconCXof128
    extends AsconXofBase
{
    private final long z0, z1, z2, z3, z4;

    public AsconCXof128()
    {
        this(new byte[0], 0, 0);
    }

    public AsconCXof128(byte[] s)
    {
        this(s, 0, s.length);
    }

    public AsconCXof128(byte[] s, int off, int len)
    {
        algorithmName = "Ascon-CXOF128";
        ensureSufficientInputBuffer(s, off, len);
        if (len > 256)
        {
            throw new DataLengthException("customized string is too long");
        }
        initState(s, off, len);
        // NOTE: Cache the initialized state
        z0 = p.x0;
        z1 = p.x1;
        z2 = p.x2;
        z3 = p.x3;
        z4 = p.x4;
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
    public void reset()
    {
        super.reset();
        /* initialize */
        p.set(z0, z1, z2, z3, z4);
    }

    private void initState(byte[] z, int zOff, int zLen)
    {
//        p.set(0x0000080000cc0004L, 0L, 0L, 0L, 0L);
//        p.p(12);

        if (zLen == 0)
        {
//            p.p(12);
//            padAndAbsorb();

            p.set(0x500cccc894e3c9e8L, 0x5bed06f28f71248dL, 0x3b03a0f930afd512L, 0x112ef093aa5c698bL, 0x00c8356340a347f0L);
        }
        else
        {
            p.set(0x675527c2a0e8de03L, 0x43d12d7dc0377bbcL, 0xe9901dec426e81b5L, 0x2ab14907720780b6L, 0x8f3f1d02d432bc46L);

            p.x0 ^= ((long)zLen) << 3;
            p.p(12);
            update(z, zOff, zLen);
            padAndAbsorb();
        }

        super.reset();
    }
}
