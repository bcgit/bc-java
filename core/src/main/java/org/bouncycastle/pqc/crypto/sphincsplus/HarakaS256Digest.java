package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.Digest;

/**
 * Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
 * <p>
 * Haraka512-256 with reference to Python Reference Impl from: https://github.com/sphincs/sphincsplus
 * </p>
 */
class HarakaS256Digest
    extends HarakaSBase
    implements Digest
{
    public HarakaS256Digest(HarakaSXof base)
    {
        haraka256_rc = base.haraka256_rc;
    }

    public String getAlgorithmName()
    {
        return "HarakaS-256";
    }

    @Override
    public int getDigestSize()
    {
        return 32;
    }

    public void update(byte in)
    {
        if (off + 1 > 32)
        {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }

        buffer[off++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (off + len > 32)
        {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }

        System.arraycopy(in, inOff, buffer, off, len);
        off += len;
    }

    public int doFinal(byte[] output, int outOff)
    {
        byte[] s = new byte[64];
        haraka256Perm(s);
        System.arraycopy(s, 0, output, outOff, output.length - outOff);

        reset();
        
        return output.length;
    }

    public void reset()
    {
        super.reset();
    }
}
