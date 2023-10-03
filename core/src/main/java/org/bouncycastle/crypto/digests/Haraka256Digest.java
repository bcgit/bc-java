package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/**
 * Haraka-256 v2, https://eprint.iacr.org/2016/098.pdf
 * <p>
 * Haraka256-256 with reference to Python Reference Impl from: https://github.com/kste/haraka
 * </p>
 */
public class Haraka256Digest
    extends HarakaBase
{
    private void mix256(byte[][] s1, byte[][] s2)
    {
        System.arraycopy(s1[0], 0, s2[0], 0, 4);
        System.arraycopy(s1[1], 0, s2[0], 4, 4);
        System.arraycopy(s1[0], 4, s2[0], 8, 4);
        System.arraycopy(s1[1], 4, s2[0], 12, 4);

        System.arraycopy(s1[0], 8, s2[1], 0, 4);
        System.arraycopy(s1[1], 8, s2[1], 4, 4);
        System.arraycopy(s1[0], 12, s2[1], 8, 4);
        System.arraycopy(s1[1], 12, s2[1], 12, 4);
    }

    private int haraka256256(byte[] msg, byte[] out, int outOff)
    {
        byte[][] s1 = new byte[2][16];
        byte[][] s2 = new byte[2][16];

        System.arraycopy(msg, 0, s1[0], 0, 16);
        System.arraycopy(msg, 16, s1[1], 0, 16);

        s1[0] = aesEnc(s1[0], RC[0]);
        s1[1] = aesEnc(s1[1], RC[1]);
        s1[0] = aesEnc(s1[0], RC[2]);
        s1[1] = aesEnc(s1[1], RC[3]);
        mix256(s1, s2);

        s1[0] = aesEnc(s2[0], RC[4]);
        s1[1] = aesEnc(s2[1], RC[5]);
        s1[0] = aesEnc(s1[0], RC[6]);
        s1[1] = aesEnc(s1[1], RC[7]);
        mix256(s1, s2);

        s1[0] = aesEnc(s2[0], RC[8]);
        s1[1] = aesEnc(s2[1], RC[9]);
        s1[0] = aesEnc(s1[0], RC[10]);
        s1[1] = aesEnc(s1[1], RC[11]);
        mix256(s1, s2);

        s1[0] = aesEnc(s2[0], RC[12]);
        s1[1] = aesEnc(s2[1], RC[13]);
        s1[0] = aesEnc(s1[0], RC[14]);
        s1[1] = aesEnc(s1[1], RC[15]);
        mix256(s1, s2);

        s1[0] = aesEnc(s2[0], RC[16]);
        s1[1] = aesEnc(s2[1], RC[17]);
        s1[0] = aesEnc(s1[0], RC[18]);
        s1[1] = aesEnc(s1[1], RC[19]);
        mix256(s1, s2);

        Bytes.xor(16, s2[0], 0, msg,  0, out, outOff);
        Bytes.xor(16, s2[1], 0, msg, 16, out, outOff + 16);

        return DIGEST_SIZE;
    }

    private final byte[] buffer;
    private int off;

    private final CryptoServicePurpose purpose;


    public Haraka256Digest()
    {
        this(CryptoServicePurpose.ANY);
    }

    public Haraka256Digest(CryptoServicePurpose purpose)
    {
        this.purpose = purpose;

        this.buffer = new byte[32];

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize()*4, purpose));
    }

    public Haraka256Digest(Haraka256Digest digest)
    {
        this.purpose = digest.purpose;

        this.buffer = Arrays.clone(digest.buffer);
        this.off = digest.off;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize()*4, purpose));
    }

    public String getAlgorithmName()
    {
        return "Haraka-256";
    }

    public void update(byte in)
    {
        if (off > 32 - 1)
        {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }

        buffer[off++] = in;
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (off > 32 - len)
        {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }

        System.arraycopy(in, inOff, buffer, off, len);
        off += len;
    }

    public int doFinal(byte[] out, int outOff)
    {
        if (off != 32)
        {
            throw new IllegalStateException("input must be exactly 32 bytes");
        }

        if (out.length - outOff < 32)
        {
            throw new IllegalArgumentException("output too short to receive digest");
        }

        int rv = haraka256256(buffer, out, outOff);

        reset();

        return rv;
    }

    public void reset()
    {
        off = 0;
        Arrays.clear(buffer);
    }
}
