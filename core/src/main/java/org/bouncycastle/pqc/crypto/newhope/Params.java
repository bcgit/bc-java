package org.bouncycastle.pqc.crypto.newhope;

class Params
{
    static final int N = 1024;
    static final int K = 16; /* used in sampler */
    static final int Q = 12289; 

    static final int POLY_BYTES = 1792;
    static final int REC_BYTES = 256;
    static final int SEED_BYTES = 32;     // care changing this one - connected to digest size used.
}
