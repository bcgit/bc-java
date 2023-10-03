package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/**
 * Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
 * <p>
 * Haraka512-256 with reference to Python Reference Impl from: https://github.com/kste/haraka
 * </p>
 */
public class Haraka512Digest
    extends HarakaBase
{
    private final byte[] buffer;
    private int off;

    private final CryptoServicePurpose purpose;


    public Haraka512Digest()
    {
        this(CryptoServicePurpose.ANY);
    }
    public Haraka512Digest(CryptoServicePurpose purpose)
    {
        this.purpose = purpose;

        this.buffer = new byte[64];
    }

    public Haraka512Digest(Haraka512Digest digest)
    {
        this.purpose = digest.purpose;

        this.buffer = Arrays.clone(digest.buffer);
        this.off = digest.off;
    }

    private void mix512(byte[][] s1, byte[][] s2)
    {
        System.arraycopy(s1[0], 12, s2[0], 0, 4);
        System.arraycopy(s1[2], 12, s2[0], 4, 4);
        System.arraycopy(s1[1], 12, s2[0], 8, 4);
        System.arraycopy(s1[3], 12, s2[0], 12, 4);

        System.arraycopy(s1[2], 0, s2[1], 0, 4);
        System.arraycopy(s1[0], 0, s2[1], 4, 4);
        System.arraycopy(s1[3], 0, s2[1], 8, 4);
        System.arraycopy(s1[1], 0, s2[1], 12, 4);

        System.arraycopy(s1[2], 4, s2[2], 0, 4);
        System.arraycopy(s1[0], 4, s2[2], 4, 4);
        System.arraycopy(s1[3], 4, s2[2], 8, 4);
        System.arraycopy(s1[1], 4, s2[2], 12, 4);

        System.arraycopy(s1[0], 8, s2[3], 0, 4);
        System.arraycopy(s1[2], 8, s2[3], 4, 4);
        System.arraycopy(s1[1], 8, s2[3], 8, 4);
        System.arraycopy(s1[3], 8, s2[3], 12, 4);
    }

    private int haraka512256(byte[] msg, byte[] out, int outOff)
    {
        byte[][] s1 = new byte[4][16];
        byte[][] s2 = new byte[4][16];

        //-- Unrolled version of above.

        System.arraycopy(msg, 0, s1[0], 0, 16);
        System.arraycopy(msg, 16, s1[1], 0, 16);
        System.arraycopy(msg, 32, s1[2], 0, 16);
        System.arraycopy(msg, 48, s1[3], 0, 16);

        s1[0] = aesEnc(s1[0], RC[0]);
        s1[1] = aesEnc(s1[1], RC[1]);
        s1[2] = aesEnc(s1[2], RC[2]);
        s1[3] = aesEnc(s1[3], RC[3]);
        s1[0] = aesEnc(s1[0], RC[4]);
        s1[1] = aesEnc(s1[1], RC[5]);
        s1[2] = aesEnc(s1[2], RC[6]);
        s1[3] = aesEnc(s1[3], RC[7]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[8]);
        s1[1] = aesEnc(s2[1], RC[9]);
        s1[2] = aesEnc(s2[2], RC[10]);
        s1[3] = aesEnc(s2[3], RC[11]);
        s1[0] = aesEnc(s1[0], RC[12]);
        s1[1] = aesEnc(s1[1], RC[13]);
        s1[2] = aesEnc(s1[2], RC[14]);
        s1[3] = aesEnc(s1[3], RC[15]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[16]);
        s1[1] = aesEnc(s2[1], RC[17]);
        s1[2] = aesEnc(s2[2], RC[18]);
        s1[3] = aesEnc(s2[3], RC[19]);
        s1[0] = aesEnc(s1[0], RC[20]);
        s1[1] = aesEnc(s1[1], RC[21]);
        s1[2] = aesEnc(s1[2], RC[22]);
        s1[3] = aesEnc(s1[3], RC[23]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[24]);
        s1[1] = aesEnc(s2[1], RC[25]);
        s1[2] = aesEnc(s2[2], RC[26]);
        s1[3] = aesEnc(s2[3], RC[27]);
        s1[0] = aesEnc(s1[0], RC[28]);
        s1[1] = aesEnc(s1[1], RC[29]);
        s1[2] = aesEnc(s1[2], RC[30]);
        s1[3] = aesEnc(s1[3], RC[31]);
        mix512(s1, s2);

        s1[0] = aesEnc(s2[0], RC[32]);
        s1[1] = aesEnc(s2[1], RC[33]);
        s1[2] = aesEnc(s2[2], RC[34]);
        s1[3] = aesEnc(s2[3], RC[35]);
        s1[0] = aesEnc(s1[0], RC[36]);
        s1[1] = aesEnc(s1[1], RC[37]);
        s1[2] = aesEnc(s1[2], RC[38]);
        s1[3] = aesEnc(s1[3], RC[39]);
        mix512(s1, s2);

        Bytes.xor(16, s2[0], 0, msg,  0, s1[0], 0);
        Bytes.xor(16, s2[1], 0, msg, 16, s1[1], 0);
        Bytes.xor(16, s2[2], 0, msg, 32, s1[2], 0);
        Bytes.xor(16, s2[3], 0, msg, 48, s1[3], 0);

        System.arraycopy(s1[0], 8, out, outOff, 8);
        System.arraycopy(s1[1], 8, out, outOff + 8, 8);
        System.arraycopy(s1[2], 0, out, outOff + 16, 8);
        System.arraycopy(s1[3], 0, out, outOff + 24, 8);

        return DIGEST_SIZE;
    }

    public String getAlgorithmName()
    {
        return "Haraka-512";
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
        if (off != 64)
        {
            throw new IllegalStateException("input must be exactly 64 bytes");
        }

        if (out.length - outOff < 32)
        {
            throw new IllegalArgumentException("output too short to receive digest");
        }

        int rv = haraka512256(buffer, out, outOff);

        reset();

        return rv;
    }

    public void reset()
    {
        off = 0;
        Arrays.clear(buffer);
    }
}
