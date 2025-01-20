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
    extends AsconXof128
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
        super(false);
        if ((off + len) > s.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        if (len > 256)
        {
            throw new DataLengthException("customized string is too long");
        }
        initState(s, off, len);
        // NOTE: Cache the initialized state
        z0 = x0;
        z1 = x1;
        z2 = x2;
        z3 = x3;
        z4 = x4;
    }

    @Override
    public String getAlgorithmName()
    {
        return "Ascon-CXOF128";
    }

    @Override
    public void reset()
    {
        baseReset();
        m_squeezing = false;
        bytesInBuffer = 0;
        /* initialize */
        x0 = z0;
        x1 = z1;
        x2 = z2;
        x3 = z3;
        x4 = z4;
    }

    private void initState(byte[] z, int zOff, int zLen)
    {
        x0 = 7445901275803737603L;
        x1 = 4886737088792722364L;
        x2 = -1616759365661982283L;
        x3 = 3076320316797452470L;
        x4 = -8124743304765850554L;
        long bitLength = ((long)zLen) << 3;
        Pack.longToLittleEndian(bitLength, m_buf, 0);
        p(12);
        update(z, zOff, zLen);
        padAndAbsorb();
        m_squeezing = false;
        bytesInBuffer = 0;
    }
}
