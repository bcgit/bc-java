package org.bouncycastle.pqc.crypto.sphincsplus;

class SIG
{
    private final byte[] r;
    private final SIG_FORS[] sig_fors;
    private final SIG_XMSS[] sig_ht;

    public SIG(int n, int k, int a, int d, int hPrime, int wots_len, byte[] signature)
    {
        this.r = new byte[n];
        System.arraycopy(signature, 0, r, 0, n);

        this.sig_fors = new SIG_FORS[k];
        int offset = n;
        for (int i = 0; i != k; i++)
        {
            byte[] sk = new byte[n];
            System.arraycopy(signature, offset, sk, 0, n);
            offset += n;
            byte[][] authPath = new byte[a][];
            for (int j = 0; j != a; j++)
            {
                authPath[j] = new byte[n];
                System.arraycopy(signature, offset, authPath[j], 0, n);
                offset += n;
            }
            sig_fors[i] = new SIG_FORS(sk, authPath);
        }

        sig_ht = new SIG_XMSS[d];
        for (int i = 0; i != d; i++)
        {
            byte[] sig = new byte[wots_len * n];
            System.arraycopy(signature, offset, sig, 0, sig.length);
            offset += sig.length;
            byte[][] authPath = new byte[hPrime][];
            for (int j = 0; j != hPrime; j++)
            {
                authPath[j] = new byte[n];
                System.arraycopy(signature, offset, authPath[j], 0, n);
                offset += n;
            }
            sig_ht[i] = new SIG_XMSS(sig, authPath);
        }
        if (offset != signature.length)
        {
            throw new IllegalArgumentException("signature wrong length");
        }
    }

    public byte[] getR()
    {
        return r;
    }

    public SIG_FORS[] getSIG_FORS()
    {
        return sig_fors;
    }

    public SIG_XMSS[] getSIG_HT()
    {
        return sig_ht;
    }
}
