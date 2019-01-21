package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Pack;

/**
 * SPHINCS-256 signer.
 * <p>
 * This implementation is heavily based on the reference implementation in SUPERCOP, the main difference being the digests used
 * for message hashing and tree construction are now configurable (within limits...) and that the implementation produces
 * detached signatures.
 * </p>
 * <p>
 * The SPHINCS reference implementation is public domain, as per the statement in the second last paragraph of
 * section 1 in https://eprint.iacr.org/2014/795.pdf
 * </p>
 */
public class SPHINCS256Signer
    implements MessageSigner
{
    private final HashFunctions hashFunctions;

    private byte[] keyData;

    /**
     * Base constructor.
     *
     * @param nDigest  the "n-digest" must produce 32 bytes of output - used for tree construction.
     * @param twoNDigest the "2n-digest" must produce 64 bytes of output - used for initial message/key/seed hashing.
     */
    public SPHINCS256Signer(Digest nDigest, Digest twoNDigest)
    {
        if (nDigest.getDigestSize() != 32)
        {
            throw new IllegalArgumentException("n-digest needs to produce 32 bytes of output");
        }
        if (twoNDigest.getDigestSize() != 64)
        {
            throw new IllegalArgumentException("2n-digest needs to produce 64 bytes of output");
        }

        this.hashFunctions = new HashFunctions(nDigest, twoNDigest);
    }

    public void init(boolean forSigning, CipherParameters param)
    {
         if (forSigning)
         {
             if (param instanceof ParametersWithRandom) {
                 // SPHINCS-256 signatures are deterministic, RNG is not required.
                 keyData = ((SPHINCSPrivateKeyParameters)((ParametersWithRandom) param).getParameters()).getKeyData();
             } else {
                 keyData = ((SPHINCSPrivateKeyParameters) param).getKeyData();
             }
         }
         else
         {
             keyData = ((SPHINCSPublicKeyParameters)param).getKeyData();
         }
    }

    public byte[] generateSignature(byte[] message)
    {
        return crypto_sign(hashFunctions, message, keyData);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return verify(hashFunctions, message, signature, keyData);
    }

    static void validate_authpath(HashFunctions hs, byte[] root, byte[] leaf, int leafidx, byte[] authpath, int auOff, byte[] masks, int height)
    {
        int i, j;
        byte[] buffer = new byte[2 * SPHINCS256Config.HASH_BYTES];

        if ((leafidx & 1) != 0)
        {
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[SPHINCS256Config.HASH_BYTES + j] = leaf[j];
            }
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[j] = authpath[auOff + j];
            }
        }
        else
        {
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[j] = leaf[j];
            }
            for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
            {
                buffer[SPHINCS256Config.HASH_BYTES + j] = authpath[auOff + j];
            }
        }
        int authOff = auOff + SPHINCS256Config.HASH_BYTES;

        for (i = 0; i < height - 1; i++)
        {
            leafidx >>>= 1;
            if ((leafidx & 1) != 0)
            {
                hs.hash_2n_n_mask(buffer, SPHINCS256Config.HASH_BYTES, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + i) * SPHINCS256Config.HASH_BYTES);
                for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
                {
                    buffer[j] = authpath[authOff + j];
                }
            }
            else
            {
                hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + i) * SPHINCS256Config.HASH_BYTES);
                for (j = 0; j < SPHINCS256Config.HASH_BYTES; j++)
                {
                    buffer[j + SPHINCS256Config.HASH_BYTES] = authpath[authOff + j];
                }
            }
            authOff += SPHINCS256Config.HASH_BYTES;
        }
        hs.hash_2n_n_mask(root, 0, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + height - 1) * SPHINCS256Config.HASH_BYTES);
    }


    static void compute_authpath_wots(HashFunctions hs, byte[] root, byte[] authpath, int authOff, Tree.leafaddr a, byte[] sk, byte[] masks, int height)
    {
        int i, idx, j;
        Tree.leafaddr ta = new Tree.leafaddr(a);

        byte[] tree = new byte[2 * (1 << SPHINCS256Config.SUBTREE_HEIGHT) * SPHINCS256Config.HASH_BYTES];
        byte[] seed = new byte[(1 << SPHINCS256Config.SUBTREE_HEIGHT) * SPHINCS256Config.SEED_BYTES];
        byte[] pk = new byte[(1 << SPHINCS256Config.SUBTREE_HEIGHT) * Wots.WOTS_L * SPHINCS256Config.HASH_BYTES];

        // level 0
        for (ta.subleaf = 0; ta.subleaf < (1 << SPHINCS256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            Seed.get_seed(hs, seed, (int)(ta.subleaf * SPHINCS256Config.SEED_BYTES), sk, ta);
        }

        Wots w = new Wots();

        for (ta.subleaf = 0; ta.subleaf < (1 << SPHINCS256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            w.wots_pkgen(hs, pk, (int)(ta.subleaf * Wots.WOTS_L * SPHINCS256Config.HASH_BYTES), seed, (int)(ta.subleaf * SPHINCS256Config.SEED_BYTES), masks, 0);
        }

        for (ta.subleaf = 0; ta.subleaf < (1 << SPHINCS256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            Tree.l_tree(hs, tree, (int)((1 << SPHINCS256Config.SUBTREE_HEIGHT) * SPHINCS256Config.HASH_BYTES + ta.subleaf * SPHINCS256Config.HASH_BYTES),
                pk, (int)(ta.subleaf * Wots.WOTS_L * SPHINCS256Config.HASH_BYTES), masks, 0);
        }

        int level = 0;

        // tree
        for (i = (1 << SPHINCS256Config.SUBTREE_HEIGHT); i > 0; i >>>= 1)
        {
            for (j = 0; j < i; j += 2)
            {
                hs.hash_2n_n_mask(tree, (i >>> 1) * SPHINCS256Config.HASH_BYTES + (j >>> 1) * SPHINCS256Config.HASH_BYTES,
                    tree, i * SPHINCS256Config.HASH_BYTES + j * SPHINCS256Config.HASH_BYTES,
                    masks, 2 * (Wots.WOTS_LOG_L + level) * SPHINCS256Config.HASH_BYTES);
            }

            level++;
        }


        idx = (int)a.subleaf;

        // copy authpath
        for (i = 0; i < height; i++)
        {
            System.arraycopy(tree, ((1 << SPHINCS256Config.SUBTREE_HEIGHT) >>> i) * SPHINCS256Config.HASH_BYTES + ((idx >>> i) ^ 1) * SPHINCS256Config.HASH_BYTES, authpath, authOff + i * SPHINCS256Config.HASH_BYTES, SPHINCS256Config.HASH_BYTES);
        }

        // copy root
        System.arraycopy(tree, SPHINCS256Config.HASH_BYTES, root, 0,  SPHINCS256Config.HASH_BYTES);
    }

    byte[] crypto_sign(HashFunctions hs, byte[] m, byte[] sk)
    {
        byte[] sm = new byte[SPHINCS256Config.CRYPTO_BYTES];

        int i;
        long leafidx;
        byte[] R = new byte[SPHINCS256Config.MESSAGE_HASH_SEED_BYTES];
        byte[] m_h = new byte[SPHINCS256Config.MSGHASH_BYTES];
        long[] rnd = new long[8];

        byte[] root = new byte[SPHINCS256Config.HASH_BYTES];
        byte[] seed = new byte[SPHINCS256Config.SEED_BYTES];
        byte[] masks = new byte[Horst.N_MASKS * SPHINCS256Config.HASH_BYTES];
        int pk;
        byte[] tsk = new byte[SPHINCS256Config.CRYPTO_SECRETKEYBYTES];

        for (i = 0; i < SPHINCS256Config.CRYPTO_SECRETKEYBYTES; i++)
        {
            tsk[i] = sk[i];
        }

        // create leafidx deterministically
        {
            // shift scratch upwards so we can reuse msg later
            int scratch = SPHINCS256Config.CRYPTO_BYTES - SPHINCS256Config.SK_RAND_SEED_BYTES;

            // Copy secret random seed to scratch
            System.arraycopy(tsk, SPHINCS256Config.CRYPTO_SECRETKEYBYTES - SPHINCS256Config.SK_RAND_SEED_BYTES, sm, scratch, SPHINCS256Config.SK_RAND_SEED_BYTES);

            Digest d = hs.getMessageHash();
            byte[] bRnd = new byte[d.getDigestSize()];

            d.update(sm, scratch, SPHINCS256Config.SK_RAND_SEED_BYTES);

            d.update(m, 0, m.length);

            d.doFinal(bRnd, 0);

            // wipe sk
            zerobytes(sm, scratch, SPHINCS256Config.SK_RAND_SEED_BYTES);

            for (int j = 0; j != rnd.length; j++)
            {
                rnd[j] = Pack.littleEndianToLong(bRnd, j * 8);
            }
            leafidx = rnd[0] & 0xfffffffffffffffL;

            System.arraycopy(bRnd, 16, R, 0, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES);

            // prepare msg_hash
            scratch = SPHINCS256Config.CRYPTO_BYTES - SPHINCS256Config.MESSAGE_HASH_SEED_BYTES - SPHINCS256Config.CRYPTO_PUBLICKEYBYTES;

            // cpy R
            System.arraycopy(R, 0, sm, scratch, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES);

            // construct and cpy pk
            Tree.leafaddr b = new Tree.leafaddr();
            b.level = SPHINCS256Config.N_LEVELS - 1;
            b.subtree = 0;
            b.subleaf = 0;

            pk = scratch + SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;

            System.arraycopy(tsk, SPHINCS256Config.SEED_BYTES, sm, pk, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);

            Tree.treehash(hs, sm, pk + (Horst.N_MASKS * SPHINCS256Config.HASH_BYTES), SPHINCS256Config.SUBTREE_HEIGHT, tsk, b, sm, pk);

            d = hs.getMessageHash();

            d.update(sm, scratch, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES + SPHINCS256Config.CRYPTO_PUBLICKEYBYTES);
            d.update(m, 0, m.length);
            d.doFinal(m_h, 0);
        }

        Tree.leafaddr a = new Tree.leafaddr();

        a.level = SPHINCS256Config.N_LEVELS; // Use unique value $d$ for HORST address.
        a.subleaf = (int)(leafidx & ((1 << SPHINCS256Config.SUBTREE_HEIGHT) - 1));
        a.subtree = leafidx >>> SPHINCS256Config.SUBTREE_HEIGHT;

        for (i = 0; i < SPHINCS256Config.MESSAGE_HASH_SEED_BYTES; i++)
        {
            sm[i] = R[i];
        }

        int smOff = SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;

        System.arraycopy(tsk, SPHINCS256Config.SEED_BYTES, masks, 0, Horst.N_MASKS * SPHINCS256Config.HASH_BYTES);
        for (i = 0; i < (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8; i++)
        {
            sm[smOff + i] = (byte)((leafidx >>> 8 * i) & 0xff);
        }

        smOff += (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;

        Seed.get_seed(hs, seed, 0, tsk, a);
        Horst ht = new Horst();

        int horst_sigbytes = ht.horst_sign(hs, sm, smOff, root, seed, masks, m_h);

        smOff += horst_sigbytes;

        Wots w = new Wots();

        for (i = 0; i < SPHINCS256Config.N_LEVELS; i++)
        {
            a.level = i;

            Seed.get_seed(hs, seed, 0, tsk, a); //XXX: Don't use the same address as for horst_sign here!

            w.wots_sign(hs, sm, smOff, root, seed, masks);

            smOff += Wots.WOTS_SIGBYTES;

            compute_authpath_wots(hs, root, sm, smOff, a, tsk, masks, SPHINCS256Config.SUBTREE_HEIGHT);
            smOff += SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;

            a.subleaf = (int)(a.subtree & ((1 << SPHINCS256Config.SUBTREE_HEIGHT) - 1));
            a.subtree >>>= SPHINCS256Config.SUBTREE_HEIGHT;
        }

        zerobytes(tsk, 0, SPHINCS256Config.CRYPTO_SECRETKEYBYTES);

        return sm;
    }

    private void zerobytes(byte[] tsk, int off, int cryptoSecretkeybytes)
    {
        for (int i = 0; i != cryptoSecretkeybytes; i++)
        {
            tsk[off + i] = 0;
        }
    }

    boolean verify(HashFunctions hs, byte[] m, byte[] sm, byte[] pk)
    {
        int i;
        int smlen = sm.length;
        long leafidx = 0;
        byte[] wots_pk = new byte[ Wots.WOTS_L * SPHINCS256Config.HASH_BYTES];
        byte[] pkhash = new byte[ SPHINCS256Config.HASH_BYTES];
        byte[] root = new byte[ SPHINCS256Config.HASH_BYTES];
        byte[] sig = new byte[ SPHINCS256Config.CRYPTO_BYTES];
        int sigp;
        byte[] tpk = new byte[ SPHINCS256Config.CRYPTO_PUBLICKEYBYTES];

        if (smlen != SPHINCS256Config.CRYPTO_BYTES)
        {
            throw new IllegalArgumentException("signature wrong size");
        }

        byte[] m_h = new byte[ SPHINCS256Config.MSGHASH_BYTES];

        for (i = 0; i < SPHINCS256Config.CRYPTO_PUBLICKEYBYTES; i++)
            tpk[i] = pk[i];

        // construct message hash
        {
            byte[] R = new byte[ SPHINCS256Config.MESSAGE_HASH_SEED_BYTES];

            for (i = 0; i < SPHINCS256Config.MESSAGE_HASH_SEED_BYTES; i++)
                R[i] = sm[i];

            System.arraycopy(sm, 0, sig, 0, SPHINCS256Config.CRYPTO_BYTES);

            Digest mHash = hs.getMessageHash();

            // input R
            mHash.update(R, 0, SPHINCS256Config.MESSAGE_HASH_SEED_BYTES);

            // input pub key
            mHash.update(tpk, 0, SPHINCS256Config.CRYPTO_PUBLICKEYBYTES);

            // input message
            mHash.update(m, 0, m.length);

            mHash.doFinal(m_h, 0);
        }

        sigp = 0;

        sigp += SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;
        smlen -= SPHINCS256Config.MESSAGE_HASH_SEED_BYTES;


        for (i = 0; i < (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8; i++)
        {
            leafidx ^= ((long)(sig[sigp + i] & 0xff) << (8 * i));
        }


        new Horst().horst_verify(hs, root, sig, sigp + (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8,
            tpk, m_h);

        sigp += (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;
        smlen -= (SPHINCS256Config.TOTALTREE_HEIGHT + 7) / 8;

        sigp += Horst.HORST_SIGBYTES;
        smlen -= Horst.HORST_SIGBYTES;

        Wots w = new Wots();

        for (i = 0; i < SPHINCS256Config.N_LEVELS; i++)
        {
            w.wots_verify(hs, wots_pk, sig, sigp, root, tpk);

            sigp += Wots.WOTS_SIGBYTES;
            smlen -= Wots.WOTS_SIGBYTES;

            Tree.l_tree(hs, pkhash, 0, wots_pk, 0, tpk, 0);
            validate_authpath(hs, root, pkhash, (int)(leafidx & 0x1f), sig, sigp, tpk, SPHINCS256Config.SUBTREE_HEIGHT);
            leafidx >>= 5;

            sigp += SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;
            smlen -= SPHINCS256Config.SUBTREE_HEIGHT * SPHINCS256Config.HASH_BYTES;
        }

        boolean verified = true;
        for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
        {
            if (root[i] != tpk[i + Horst.N_MASKS * SPHINCS256Config.HASH_BYTES])
            {
                verified = false;
            }
        }

        return verified;
    }
}

