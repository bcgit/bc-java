package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Pack;

/**
 * SPHINCS-256 signer.
 * <p>
 * This implementation is heavily based on the reference implementation in SUPERCOP, the main difference being the digests used
 * for message hashing and tree construction are now configurable (within limits...)
 * </p>
 */
public class Sphincs256Signer
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
    public Sphincs256Signer(Digest nDigest, Digest twoNDigest)
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
             keyData = ((SphincsPrivateKeyParameters)param).getKeyData();
         }
         else
         {
             keyData = ((SphincsPublicKeyParameters)param).getKeyData();
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
        byte[] buffer = new byte[2 * Sphincs256Config.HASH_BYTES];

        if ((leafidx & 1) != 0)
        {
            for (j = 0; j < Sphincs256Config.HASH_BYTES; j++)
            {
                buffer[Sphincs256Config.HASH_BYTES + j] = leaf[j];
            }
            for (j = 0; j < Sphincs256Config.HASH_BYTES; j++)
            {
                buffer[j] = authpath[auOff + j];
            }
        }
        else
        {
            for (j = 0; j < Sphincs256Config.HASH_BYTES; j++)
            {
                buffer[j] = leaf[j];
            }
            for (j = 0; j < Sphincs256Config.HASH_BYTES; j++)
            {
                buffer[Sphincs256Config.HASH_BYTES + j] = authpath[auOff + j];
            }
        }
        int authOff = auOff + Sphincs256Config.HASH_BYTES;

        for (i = 0; i < height - 1; i++)
        {
            leafidx >>>= 1;
            if ((leafidx & 1) != 0)
            {
                hs.hash_2n_n_mask(buffer, Sphincs256Config.HASH_BYTES, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + i) * Sphincs256Config.HASH_BYTES);
                for (j = 0; j < Sphincs256Config.HASH_BYTES; j++)
                {
                    buffer[j] = authpath[authOff + j];
                }
            }
            else
            {
                hs.hash_2n_n_mask(buffer, 0, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + i) * Sphincs256Config.HASH_BYTES);
                for (j = 0; j < Sphincs256Config.HASH_BYTES; j++)
                {
                    buffer[j + Sphincs256Config.HASH_BYTES] = authpath[authOff + j];
                }
            }
            authOff += Sphincs256Config.HASH_BYTES;
        }
        hs.hash_2n_n_mask(root, 0, buffer, 0, masks, 2 * (Wots.WOTS_LOG_L + height - 1) * Sphincs256Config.HASH_BYTES);
    }


    static void compute_authpath_wots(HashFunctions hs, byte[] root, byte[] authpath, int authOff, Tree.leafaddr a, byte[] sk, byte[] masks, int height)
    {
        int i, idx, j;
        Tree.leafaddr ta = new Tree.leafaddr(a);

        byte[] tree = new byte[2 * (1 << Sphincs256Config.SUBTREE_HEIGHT) * Sphincs256Config.HASH_BYTES];
        byte[] seed = new byte[(1 << Sphincs256Config.SUBTREE_HEIGHT) * Sphincs256Config.SEED_BYTES];
        byte[] pk = new byte[(1 << Sphincs256Config.SUBTREE_HEIGHT) * Wots.WOTS_L * Sphincs256Config.HASH_BYTES];

        // level 0
        for (ta.subleaf = 0; ta.subleaf < (1 << Sphincs256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            Seed.get_seed(hs, seed, (int)(ta.subleaf * Sphincs256Config.SEED_BYTES), sk, ta);
        }

        Wots w = new Wots();

        for (ta.subleaf = 0; ta.subleaf < (1 << Sphincs256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            w.wots_pkgen(hs, pk, (int)(ta.subleaf * Wots.WOTS_L * Sphincs256Config.HASH_BYTES), seed, (int)(ta.subleaf * Sphincs256Config.SEED_BYTES), masks, 0);
        }

        for (ta.subleaf = 0; ta.subleaf < (1 << Sphincs256Config.SUBTREE_HEIGHT); ta.subleaf++)
        {
            Tree.l_tree(hs, tree, (int)((1 << Sphincs256Config.SUBTREE_HEIGHT) * Sphincs256Config.HASH_BYTES + ta.subleaf * Sphincs256Config.HASH_BYTES),
                pk, (int)(ta.subleaf * Wots.WOTS_L * Sphincs256Config.HASH_BYTES), masks, 0);
        }

        int level = 0;

        // tree
        for (i = (1 << Sphincs256Config.SUBTREE_HEIGHT); i > 0; i >>>= 1)
        {
            for (j = 0; j < i; j += 2)
            {
                hs.hash_2n_n_mask(tree, (i >>> 1) * Sphincs256Config.HASH_BYTES + (j >>> 1) * Sphincs256Config.HASH_BYTES,
                    tree, i * Sphincs256Config.HASH_BYTES + j * Sphincs256Config.HASH_BYTES,
                    masks, 2 * (Wots.WOTS_LOG_L + level) * Sphincs256Config.HASH_BYTES);
            }

            level++;
        }


        idx = (int)a.subleaf;

        // copy authpath
        for (i = 0; i < height; i++)
        {
            System.arraycopy(tree, ((1 << Sphincs256Config.SUBTREE_HEIGHT) >>> i) * Sphincs256Config.HASH_BYTES + ((idx >>> i) ^ 1) * Sphincs256Config.HASH_BYTES, authpath, authOff + i * Sphincs256Config.HASH_BYTES, Sphincs256Config.HASH_BYTES);
        }

        // copy root
        System.arraycopy(tree, Sphincs256Config.HASH_BYTES, root, 0,  Sphincs256Config.HASH_BYTES);
    }

    byte[] crypto_sign(HashFunctions hs, byte[] m, byte[] sk)
    {
        byte[] sm = new byte[Sphincs256Config.CRYPTO_BYTES];

        int i;
        long leafidx;
        byte[] R = new byte[Sphincs256Config.MESSAGE_HASH_SEED_BYTES];
        byte[] m_h = new byte[Sphincs256Config.MSGHASH_BYTES];
        long[] rnd = new long[8];

        byte[] root = new byte[Sphincs256Config.HASH_BYTES];
        byte[] seed = new byte[Sphincs256Config.SEED_BYTES];
        byte[] masks = new byte[Horst.N_MASKS * Sphincs256Config.HASH_BYTES];
        int pk;
        byte[] tsk = new byte[Sphincs256Config.CRYPTO_SECRETKEYBYTES];

        for (i = 0; i < Sphincs256Config.CRYPTO_SECRETKEYBYTES; i++)
        {
            tsk[i] = sk[i];
        }

        // create leafidx deterministically
        {
            // shift scratch upwards so we can reuse msg later
            int scratch = Sphincs256Config.CRYPTO_BYTES - Sphincs256Config.SK_RAND_SEED_BYTES;

            // Copy secret random seed to scratch
            System.arraycopy(tsk, Sphincs256Config.CRYPTO_SECRETKEYBYTES - Sphincs256Config.SK_RAND_SEED_BYTES, sm, scratch, Sphincs256Config.SK_RAND_SEED_BYTES);

            Digest d = hs.getMessageHash();
            byte[] bRnd = new byte[d.getDigestSize()];

            d.update(sm, scratch, Sphincs256Config.SK_RAND_SEED_BYTES);

            d.update(m, 0, m.length);

            d.doFinal(bRnd, 0);

            // wipe sk
            zerobytes(sm, scratch, Sphincs256Config.SK_RAND_SEED_BYTES);

            for (int j = 0; j != rnd.length; j++)
            {
                rnd[j] = Pack.littleEndianToLong(bRnd, j * 8);
            }
            leafidx = rnd[0] & 0xfffffffffffffffL;

            System.arraycopy(bRnd, 16, R, 0, Sphincs256Config.MESSAGE_HASH_SEED_BYTES);

            // prepare msg_hash
            scratch = Sphincs256Config.CRYPTO_BYTES - Sphincs256Config.MESSAGE_HASH_SEED_BYTES - Sphincs256Config.CRYPTO_PUBLICKEYBYTES;

            // cpy R
            System.arraycopy(R, 0, sm, scratch, Sphincs256Config.MESSAGE_HASH_SEED_BYTES);

            // construct and cpy pk
            Tree.leafaddr b = new Tree.leafaddr();
            b.level = Sphincs256Config.N_LEVELS - 1;
            b.subtree = 0;
            b.subleaf = 0;

            pk = scratch + Sphincs256Config.MESSAGE_HASH_SEED_BYTES;

            System.arraycopy(tsk, Sphincs256Config.SEED_BYTES, sm, pk, Horst.N_MASKS * Sphincs256Config.HASH_BYTES);

            Tree.treehash(hs, sm, pk + (Horst.N_MASKS * Sphincs256Config.HASH_BYTES), Sphincs256Config.SUBTREE_HEIGHT, tsk, b, sm, pk);

            d = hs.getMessageHash();

            d.update(sm, scratch, Sphincs256Config.MESSAGE_HASH_SEED_BYTES + Sphincs256Config.CRYPTO_PUBLICKEYBYTES);
            d.update(m, 0, m.length);
            d.doFinal(m_h, 0);
        }

        Tree.leafaddr a = new Tree.leafaddr();

        a.level = Sphincs256Config.N_LEVELS; // Use unique value $d$ for HORST address.
        a.subleaf = (int)(leafidx & ((1 << Sphincs256Config.SUBTREE_HEIGHT) - 1));
        a.subtree = leafidx >>> Sphincs256Config.SUBTREE_HEIGHT;

        int smlen = 0;

        for (i = 0; i < Sphincs256Config.MESSAGE_HASH_SEED_BYTES; i++)
        {
            sm[i] = R[i];
        }

        int smOff = Sphincs256Config.MESSAGE_HASH_SEED_BYTES;
        smlen += Sphincs256Config.MESSAGE_HASH_SEED_BYTES;

        System.arraycopy(tsk, Sphincs256Config.SEED_BYTES, masks, 0, Horst.N_MASKS * Sphincs256Config.HASH_BYTES);
        for (i = 0; i < (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8; i++)
        {
            sm[smOff + i] = (byte)((leafidx >>> 8 * i) & 0xff);
        }

        smOff += (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8;
        smlen += (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8;

        Seed.get_seed(hs, seed, 0, tsk, a);
        Horst ht = new Horst();

        long[] horst_sigbytes = new long[1];

        ht.horst_sign(hs, sm, smOff, root, horst_sigbytes, seed, masks, m_h);

        smOff += horst_sigbytes[0];
        smlen += horst_sigbytes[0];

        Wots w = new Wots();

        for (i = 0; i < Sphincs256Config.N_LEVELS; i++)
        {
            a.level = i;

            Seed.get_seed(hs, seed, 0, tsk, a); //XXX: Don't use the same address as for horst_sign here!

            w.wots_sign(hs, sm, smOff, root, seed, masks);

            smOff += Wots.WOTS_SIGBYTES;
            smlen += Wots.WOTS_SIGBYTES;

            compute_authpath_wots(hs, root, sm, smOff, a, tsk, masks, Sphincs256Config.SUBTREE_HEIGHT);
            smOff += Sphincs256Config.SUBTREE_HEIGHT * Sphincs256Config.HASH_BYTES;
            smlen += Sphincs256Config.SUBTREE_HEIGHT * Sphincs256Config.HASH_BYTES;

            a.subleaf = (int)(a.subtree & ((1 << Sphincs256Config.SUBTREE_HEIGHT) - 1));
            a.subtree >>>= Sphincs256Config.SUBTREE_HEIGHT;
        }

        zerobytes(tsk, 0, Sphincs256Config.CRYPTO_SECRETKEYBYTES);

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
        byte[] wots_pk = new byte[ Wots.WOTS_L * Sphincs256Config.HASH_BYTES];
        byte[] pkhash = new byte[ Sphincs256Config.HASH_BYTES];
        byte[] root = new byte[ Sphincs256Config.HASH_BYTES];
        byte[] sig = new byte[ Sphincs256Config.CRYPTO_BYTES];
        int sigp;
        byte[] tpk = new byte[ Sphincs256Config.CRYPTO_PUBLICKEYBYTES];

        if (smlen != Sphincs256Config.CRYPTO_BYTES)
        {
            throw new IllegalArgumentException("signature wrong size");
        }

        byte[] m_h = new byte[ Sphincs256Config.MSGHASH_BYTES];

        for (i = 0; i < Sphincs256Config.CRYPTO_PUBLICKEYBYTES; i++)
            tpk[i] = pk[i];

        // construct message hash
        {
            byte[] R = new byte[ Sphincs256Config.MESSAGE_HASH_SEED_BYTES];

            for (i = 0; i < Sphincs256Config.MESSAGE_HASH_SEED_BYTES; i++)
                R[i] = sm[i];

            System.arraycopy(sm, 0, sig, 0, Sphincs256Config.CRYPTO_BYTES);

            Digest mHash = hs.getMessageHash();

            // input R
            mHash.update(R, 0, Sphincs256Config.MESSAGE_HASH_SEED_BYTES);

            // input pub key
            mHash.update(tpk, 0, Sphincs256Config.CRYPTO_PUBLICKEYBYTES);

            // input message
            mHash.update(m, 0, m.length);

            mHash.doFinal(m_h, 0);
        }

        sigp = 0;

        sigp += Sphincs256Config.MESSAGE_HASH_SEED_BYTES;
        smlen -= Sphincs256Config.MESSAGE_HASH_SEED_BYTES;


        for (i = 0; i < (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8; i++)
        {
            leafidx ^= ((long)(sig[sigp + i] & 0xff) << (8 * i));
        }


        new Horst().horst_verify(hs, root, sig, sigp + (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8,
            tpk, m_h);

        sigp += (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8;
        smlen -= (Sphincs256Config.TOTALTREE_HEIGHT + 7) / 8;

        sigp += Horst.HORST_SIGBYTES;
        smlen -= Horst.HORST_SIGBYTES;

        Wots w = new Wots();

        for (i = 0; i < Sphincs256Config.N_LEVELS; i++)
        {
            w.wots_verify(hs, wots_pk, sig, sigp, root, tpk);

            sigp += Wots.WOTS_SIGBYTES;
            smlen -= Wots.WOTS_SIGBYTES;

            Tree.l_tree(hs, pkhash, 0, wots_pk, 0, tpk, 0);
            validate_authpath(hs, root, pkhash, (int)(leafidx & 0x1f), sig, sigp, tpk, Sphincs256Config.SUBTREE_HEIGHT);
            leafidx >>= 5;

            sigp += Sphincs256Config.SUBTREE_HEIGHT * Sphincs256Config.HASH_BYTES;
            smlen -= Sphincs256Config.SUBTREE_HEIGHT * Sphincs256Config.HASH_BYTES;
        }

        boolean verified = true;
        for (i = 0; i < Sphincs256Config.HASH_BYTES; i++)
        {
            if (root[i] != tpk[i + Horst.N_MASKS * Sphincs256Config.HASH_BYTES])
            {
                verified = false;
            }
        }

        return verified;
    }
}

