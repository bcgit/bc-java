package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.Digest;

/**
 * Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
 * <p>
 * Haraka512-256 with reference to Python Reference Impl from: https://github.com/sphincs/sphincsplus
 * </p>
 */
class HarakaS512Digest
    extends HarakaSBase
    implements Digest
{
    public HarakaS512Digest(HarakaSXof base)
    {
        haraka512_rc = base.haraka512_rc;
    }

    public String getAlgorithmName()
    {
        return "HarakaS-512";
    }

    @Override
    public int getDigestSize()
    {
        return 64;
    }

    public void update(byte in)
    {
        if (off + 1 > 64)
        {
            throw new IllegalArgumentException("total input cannot be more than 64 bytes");
        }
        buffer[off++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (off + len > 64)
        {
            throw new IllegalArgumentException("total input cannot be more than 64 bytes");
        }
        System.arraycopy(in, inOff, buffer, off, len);
        off += len;
    }


    public int doFinal(byte[] out, int outOff)
    {
        byte[] s = new byte[64];
        haraka512Perm(s);
        for (int i = 0; i < 64; ++i)
        {
            s[i] ^= buffer[i];
        }
        System.arraycopy(s, 8, out, outOff, 8);
        System.arraycopy(s, 24, out, outOff + 8, 8);
        System.arraycopy(s, 32, out, outOff + 16, 8);
        System.arraycopy(s, 48, out, outOff + 24, 8);

        reset();

        return s.length;
    }

    public void reset()
    {
        super.reset();
    }
}
