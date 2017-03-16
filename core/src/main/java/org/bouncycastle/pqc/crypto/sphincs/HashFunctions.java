package org.bouncycastle.pqc.crypto.sphincs;


import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Strings;


class HashFunctions
{
    private static final byte[] hashc = Strings.toByteArray("expand 32-byte to 64-byte state!");

    private final Digest dig256;
    private final Digest dig512;
    private final Permute perm = new Permute();

    // for key pair generation where message hash not required
    HashFunctions(Digest dig256)
    {
        this(dig256, null);
    }

    HashFunctions(Digest dig256, Digest dig512)
    {
        this.dig256 = dig256;
        this.dig512 = dig512;
    }

    int varlen_hash(byte[] out, int outOff, byte[] in, int inLen)
    {
        dig256.update(in, 0, inLen);

        dig256.doFinal(out, outOff);

        return 0;
    }

    Digest getMessageHash()
    {
        return dig512;
    }

    int hash_2n_n(byte[] out, int outOff, byte[] in, int inOff)
    {
        byte[] x = new byte[64];
        int i;
        for (i = 0; i < 32; i++)
        {
            x[i] = in[inOff + i];
            x[i + 32] = hashc[i];
        }
        perm.chacha_permute(x, x);
        for (i = 0; i < 32; i++)
        {
            x[i] = (byte)(x[i] ^ in[inOff + i + 32]);
        }
        perm.chacha_permute(x, x);
        for (i = 0; i < 32; i++)
        {
            out[outOff + i] = x[i];
        }

        return 0;
    }

    int hash_2n_n_mask(byte[] out, int outOff, byte[] in, int inOff, byte[] mask, int maskOff)
    {
        byte[] buf = new byte[2 * SPHINCS256Config.HASH_BYTES];
        int i;
        for (i = 0; i < 2 * SPHINCS256Config.HASH_BYTES; i++)
        {
            buf[i] = (byte)(in[inOff + i] ^ mask[maskOff + i]);
        }

        int rv = hash_2n_n(out, outOff, buf, 0);

        return rv;
    }

    int hash_n_n(byte[] out, int outOff, byte[] in, int inOff)
    {

        byte[] x = new byte[64];
        int i;

        for (i = 0; i < 32; i++)
        {
            x[i] = in[inOff + i];
            x[i + 32] = hashc[i];
        }
        perm.chacha_permute(x, x);
        for (i = 0; i < 32; i++)
        {
            out[outOff + i] = x[i];
        }

        return 0;
    }

    int hash_n_n_mask(byte[] out, int outOff, byte[] in, int inOff,  byte[] mask, int maskOff)
    {
        byte[] buf = new byte[SPHINCS256Config.HASH_BYTES];
        int i;
        for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
        {
            buf[i] = (byte)(in[inOff + i] ^ mask[maskOff + i]);
        }
        return hash_n_n(out, outOff, buf, 0);
    }
}

