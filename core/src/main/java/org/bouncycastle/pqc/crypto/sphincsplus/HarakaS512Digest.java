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

    public int getDigestSize()
    {
        return 32;
    }

    public void update(byte in)
    {
        if (off > 64 - 1)
        {
            throw new IllegalArgumentException("total input cannot be more than 64 bytes");
        }
        buffer[off++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (off > 64 - len)
        {
            throw new IllegalArgumentException("total input cannot be more than 64 bytes");
        }
        System.arraycopy(in, inOff, buffer, off, len);
        off += len;
    }

    public int doFinal(byte[] out, int outOff)
    {
        // TODO Check received all 64 bytes of input?

        byte[] s = new byte[64];
        haraka512Perm(s);
        xor(s,  8, buffer,  8, out, outOff     ,  8);
        xor(s, 24, buffer, 24, out, outOff +  8, 16);
        xor(s, 48, buffer, 48, out, outOff + 24,  8);

        reset();

        return s.length;
    }

    public void reset()
    {
        super.reset();
    }
}
