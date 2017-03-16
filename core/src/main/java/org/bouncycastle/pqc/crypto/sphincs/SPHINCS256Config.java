package org.bouncycastle.pqc.crypto.sphincs;

class SPHINCS256Config
{
    static final int SUBTREE_HEIGHT = 5;
    static final int TOTALTREE_HEIGHT = 60;
    static final int N_LEVELS = (TOTALTREE_HEIGHT / SUBTREE_HEIGHT);
    static final int SEED_BYTES = 32;

    static final int SK_RAND_SEED_BYTES = 32;
    static final int MESSAGE_HASH_SEED_BYTES = 32;

    static final int HASH_BYTES = 32; // Has to be log(HORST_T)*HORST_K/8
    static final int MSGHASH_BYTES = 64;

    static final int CRYPTO_PUBLICKEYBYTES = ((Horst.N_MASKS + 1) * HASH_BYTES);
    static final int CRYPTO_SECRETKEYBYTES = (SEED_BYTES + CRYPTO_PUBLICKEYBYTES - HASH_BYTES + SK_RAND_SEED_BYTES);
    static final int CRYPTO_BYTES = (MESSAGE_HASH_SEED_BYTES + (TOTALTREE_HEIGHT + 7) / 8 + Horst.HORST_SIGBYTES + (TOTALTREE_HEIGHT / SUBTREE_HEIGHT) * Wots.WOTS_SIGBYTES + TOTALTREE_HEIGHT * HASH_BYTES);
}
