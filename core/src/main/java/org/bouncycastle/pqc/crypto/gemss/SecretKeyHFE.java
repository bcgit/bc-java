package org.bouncycastle.pqc.crypto.gemss;

class SecretKeyHFE
{
    static class complete_sparse_monic_gf2nx
    {
        public Pointer poly;
        /* List of the successive differences of the exponents of the monomials of
           poly multiplied by NB_WORD_GFqn */
        public int[] L;

        public complete_sparse_monic_gf2nx()
        {
        }
    }

    complete_sparse_monic_gf2nx F_struct;
    public Pointer F_HFEv;

    public Pointer S;

    public Pointer T;

    public Pointer sk_uncomp;


    public SecretKeyHFE(GeMSSEngine engine)
    {
        F_struct = new complete_sparse_monic_gf2nx();
        F_struct.L = new int[engine.NB_COEFS_HFEPOLY];
    }
}
