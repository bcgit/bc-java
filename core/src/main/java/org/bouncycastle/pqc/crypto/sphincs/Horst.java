package org.bouncycastle.pqc.crypto.sphincs;

class Horst
{
    static final int HORST_LOGT = 16;
    static final int HORST_T = (1<<HORST_LOGT);
    static final int HORST_K = 32;
    static final int HORST_SKBYTES = 32;
    static final int HORST_SIGBYTES = (64* SPHINCS256Config.HASH_BYTES+(((HORST_LOGT-6)* SPHINCS256Config.HASH_BYTES)+HORST_SKBYTES)*HORST_K);

    static final int N_MASKS = (2*(Horst.HORST_LOGT)); /* has to be the max of  (2*(SUBTREE_HEIGHT+WOTS_LOGL)) and (WOTS_W-1) and 2*HORST_LOGT */

    static void expand_seed(byte[] outseeds, byte[] inseed)
    {
        Seed.prg(outseeds, 0, HORST_T * HORST_SKBYTES, inseed, 0);
    }

    static int horst_sign(HashFunctions hs,
                          byte[] sig, int sigOff, byte[] pk,
                   byte[] seed,
                   byte[] masks,
                   byte[] m_hash)
    {
        byte[] sk = new byte[ HORST_T * HORST_SKBYTES];
        int idx;
        int i, j, k;
        int sigpos = sigOff;

        byte[] tree = new byte[(2 * HORST_T - 1) * SPHINCS256Config.HASH_BYTES]; /* replace by something more memory-efficient? */

        expand_seed(sk, seed);

        // Build the whole tree and save it

        // Generate pk leaves
        for (i = 0; i < HORST_T; i++)
        {
            hs.hash_n_n(tree, (HORST_T - 1 + i) * SPHINCS256Config.HASH_BYTES, sk, i * HORST_SKBYTES);
        }

        long offset_in, offset_out;
        for (i = 0; i < HORST_LOGT; i++)
        {
            offset_in = (1 << (HORST_LOGT - i)) - 1;
            offset_out = (1 << (HORST_LOGT - i - 1)) - 1;
            for (j = 0; j < (1 << (HORST_LOGT - i - 1)); j++)
            {
                hs.hash_2n_n_mask(tree, (int)((offset_out + j) * SPHINCS256Config.HASH_BYTES), tree, (int)((offset_in + 2 * j) * SPHINCS256Config.HASH_BYTES), masks, 2 * i * SPHINCS256Config.HASH_BYTES);
            }
        }

        // First write 64 hashes from level 10 to the signature
        for (j = 63 * SPHINCS256Config.HASH_BYTES; j < 127 * SPHINCS256Config.HASH_BYTES; j++)
        {
            sig[sigpos++] = tree[j];
        }

        // Signature consists of HORST_K parts; each part of secret key and HORST_LOGT-4 auth-path hashes
        for (i = 0; i < HORST_K; i++)
        {
            idx = (m_hash[2 * i] & 0xff) + ((m_hash[2 * i + 1] & 0xff) << 8);

            for (k = 0; k < HORST_SKBYTES; k++)
                sig[sigpos++] = sk[idx * HORST_SKBYTES + k];

            idx += (HORST_T - 1);
            for (j = 0; j < HORST_LOGT - 6; j++)
            {
                idx = ((idx & 1) != 0) ? idx + 1 : idx - 1; // neighbor node
                for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                    sig[sigpos++] = tree[idx * SPHINCS256Config.HASH_BYTES + k];
                idx = (idx - 1) / 2; // parent node
            }
        }

        for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
        {
            pk[i] = tree[i];
        }

        return HORST_SIGBYTES;
    }

    static int horst_verify(HashFunctions hs, byte[] pk, byte[] sig, int sigOff, byte[] masks, byte[] m_hash)
    {
        byte[] buffer = new byte[ 32 * SPHINCS256Config.HASH_BYTES];

        int idx;
        int i, j, k;

        int sigOffset = sigOff + 64 * SPHINCS256Config.HASH_BYTES;

        for (i = 0; i < HORST_K; i++)
        {
            idx = (m_hash[2 * i] & 0xff) + ((m_hash[2 * i + 1] & 0xff) << 8);

            if ((idx & 1) == 0)
            {
                hs.hash_n_n(buffer, 0, sig, sigOffset);
                for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                    buffer[SPHINCS256Config.HASH_BYTES + k] = sig[sigOffset + HORST_SKBYTES + k];
            }
            else
            {
                hs.hash_n_n(buffer, SPHINCS256Config.HASH_BYTES, sig, sigOffset);
                for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                    buffer[k] = sig[sigOffset + HORST_SKBYTES + k];
            }
            sigOffset += HORST_SKBYTES + SPHINCS256Config.HASH_BYTES;

            for (j = 1; j < HORST_LOGT - 6; j++)
            {
                idx = idx >>> 1; // parent node

                if ((idx & 1) == 0)
                {
                    hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (j - 1) * SPHINCS256Config.HASH_BYTES);
                    for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                        buffer[SPHINCS256Config.HASH_BYTES + k] = sig[sigOffset + k];
                }
                else
                {

                    hs.hash_2n_n_mask(buffer, SPHINCS256Config.HASH_BYTES, buffer, 0, masks, 2 * (j - 1) * SPHINCS256Config.HASH_BYTES);
                    for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                        buffer[k] = sig[sigOffset + k];
                }
                sigOffset += SPHINCS256Config.HASH_BYTES;
            }

            idx = idx >>> 1; // parent node
            hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (HORST_LOGT - 7) * SPHINCS256Config.HASH_BYTES);

            for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                if (sig[sigOff + idx * SPHINCS256Config.HASH_BYTES + k] != buffer[k])
                {
                    for (k = 0; k < SPHINCS256Config.HASH_BYTES; k++)
                        pk[k] = 0;
                    return -1;
                }
        }

        // Compute root from level10
        for (j = 0; j < 32; j++)
        {
            hs.hash_2n_n_mask(buffer, j * SPHINCS256Config.HASH_BYTES, sig, sigOff + 2 * j * SPHINCS256Config.HASH_BYTES, masks, 2 * (HORST_LOGT - 6) * SPHINCS256Config.HASH_BYTES);
        }

        // Hash from level 11 to 12
        for (j = 0; j < 16; j++)
        {
            hs.hash_2n_n_mask(buffer, j * SPHINCS256Config.HASH_BYTES, buffer, 2 * j * SPHINCS256Config.HASH_BYTES, masks, 2 * (HORST_LOGT - 5) * SPHINCS256Config.HASH_BYTES);
        }

        // Hash from level 12 to 13
        for (j = 0; j < 8; j++)
        {
            hs.hash_2n_n_mask(buffer, j * SPHINCS256Config.HASH_BYTES, buffer, 2 * j * SPHINCS256Config.HASH_BYTES, masks, 2 * (HORST_LOGT - 4) * SPHINCS256Config.HASH_BYTES);
        }

        // Hash from level 13 to 14
        for (j = 0; j < 4; j++)
        {
            hs.hash_2n_n_mask(buffer, j * SPHINCS256Config.HASH_BYTES, buffer, 2 * j * SPHINCS256Config.HASH_BYTES, masks, 2 * (HORST_LOGT - 3) * SPHINCS256Config.HASH_BYTES);
        }

        // Hash from level 14 to 15
        for (j = 0; j < 2; j++)
        {
            hs.hash_2n_n_mask(buffer, j * SPHINCS256Config.HASH_BYTES, buffer, 2 * j * SPHINCS256Config.HASH_BYTES, masks, 2 * (HORST_LOGT - 2) * SPHINCS256Config.HASH_BYTES);
        }

        // Hash from level 15 to 16
        hs.hash_2n_n_mask(pk, 0, buffer, 0, masks, 2 * (HORST_LOGT - 1) * SPHINCS256Config.HASH_BYTES);

        return 0;
    }
}

