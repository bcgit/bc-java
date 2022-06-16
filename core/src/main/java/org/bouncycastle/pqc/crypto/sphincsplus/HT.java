package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.LinkedList;

import org.bouncycastle.util.Arrays;

class HT
{
    private final byte[] skSeed;
    private final byte[] pkSeed;
    SPHINCSPlusEngine engine;
    WotsPlus wots;

    final byte[] htPubKey;

    public HT(SPHINCSPlusEngine engine, byte[] skSeed, byte[] pkSeed)
    {
        this.skSeed = skSeed;
        this.pkSeed = pkSeed;

        this.engine = engine;
        this.wots = new WotsPlus(engine);

        ADRS adrs = new ADRS();
        adrs.setLayerAddress(engine.D - 1);
        adrs.setTreeAddress(0);

        if (skSeed != null)
        {
            htPubKey = xmss_PKgen(skSeed, pkSeed, adrs);
        }
        else
        {
            htPubKey = null;
        }
    }

    byte[] sign(byte[] M, long idx_tree, int idx_leaf)
    {
        // init
        ADRS adrs = new ADRS();
        // sign
       // adrs.setType(ADRS.TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        SIG_XMSS SIG_tmp = xmss_sign(M, skSeed, idx_leaf, pkSeed, adrs);
        SIG_XMSS[] SIG_HT = new SIG_XMSS[engine.D];
        SIG_HT[0] = SIG_tmp;

        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);

        byte[] root = xmss_pkFromSig(idx_leaf, SIG_tmp, M, pkSeed, adrs);

        for (int j = 1; j < engine.D; j++)
        {
            idx_leaf = (int)(idx_tree & ((1 << engine.H_PRIME) - 1));  // least significant bits of idx_tree;
            idx_tree >>>= engine.H_PRIME; // most significant bits of idx_tree;
            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idx_tree);
            SIG_tmp = xmss_sign(root, skSeed, idx_leaf, pkSeed, adrs);
            SIG_HT[j] = SIG_tmp;
            if (j < engine.D - 1)
            {
                root = xmss_pkFromSig(idx_leaf, SIG_tmp, root, pkSeed, adrs);
            }
        }

        byte[][] totSigs = new byte[SIG_HT.length][];
        for (int i = 0; i != totSigs.length; i++)
        {
            totSigs[i] = Arrays.concatenate(SIG_HT[i].sig, Arrays.concatenate(SIG_HT[i].auth));
        }

        return Arrays.concatenate(totSigs);
    }

    byte[] xmss_PKgen(byte[] skSeed, byte[] pkSeed, ADRS adrs)
    {
        return treehash(skSeed, 0, engine.H_PRIME, pkSeed, adrs);
    }

    // Input: index idx, XMSS signature SIG_XMSS = (sig || AUTH), n-byte message M, public seed PK.seed, address ADRS
    // Output: n-byte root value node[0]
    byte[] xmss_pkFromSig(int idx, SIG_XMSS sig_xmss, byte[] M, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS adrs = new ADRS(paramAdrs);

        // compute WOTS+ pk from WOTS+ sig
        adrs.setType(ADRS.WOTS_HASH);
        adrs.setKeyPairAddress(idx);
        byte[] sig = sig_xmss.getWOTSSig();
        byte[][] AUTH = sig_xmss.getXMSSAUTH();

        byte[] node0 = wots.pkFromSig(sig, M, pkSeed, adrs);
        byte[] node1 = null;

        // compute root from WOTS+ pk and AUTH
        adrs.setType(ADRS.TREE);
        adrs.setTreeIndex(idx);
        for (int k = 0; k < engine.H_PRIME; k++)
        {
            adrs.setTreeHeight(k + 1);
            if (((idx / (1 << k)) % 2) == 0)
            {
                adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                node1 = engine.H(pkSeed, adrs, node0, AUTH[k]);
            }
            else
            {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                node1 = engine.H(pkSeed, adrs, AUTH[k], node0);
            }
            node0 = node1;
        }
        return node0;
    }

    //    # Input: n-byte message M, secret seed SK.seed, index idx, public seed PK.seed,
    //    address ADRS
    //    # Output: XMSS signature SIG_XMSS = (sig || AUTH)
    SIG_XMSS xmss_sign(byte[] M, byte[] skSeed, int idx, byte[] pkSeed, ADRS paramAdrs)
    {
        byte[][] AUTH = new byte[engine.H_PRIME][];

        ADRS adrs = new ADRS(paramAdrs);

        adrs.setType(ADRS.TREE);
        adrs.setLayerAddress(paramAdrs.getLayerAddress());
        adrs.setTreeAddress(paramAdrs.getTreeAddress());

        // build authentication path
        for (int j = 0; j < engine.H_PRIME; j++)
        {
            int k = (idx / (1 << j)) ^ 1;
            AUTH[j] = treehash(skSeed, k * (1 << j), j, pkSeed, adrs);
        }
        adrs = new ADRS(paramAdrs);
        adrs.setType(ADRS.WOTS_PK);
        adrs.setKeyPairAddress(idx);

        byte[] sig = wots.sign(M, skSeed, pkSeed, adrs);

        return new SIG_XMSS(sig, AUTH);
    }

    //
    // Input: Secret seed SK.seed, start index s, target node height z, public seed
    //PK.seed, address ADRS
    // Output: n-byte root node - top node on Stack
    byte[] treehash(byte[] skSeed, int s, int z, byte[] pkSeed, ADRS adrsParam)
    {
        ADRS adrs = new ADRS(adrsParam);

        LinkedList<NodeEntry> stack = new LinkedList<NodeEntry>();

        if (s % (1 << z) != 0)
        {
            return null;
        }

        for (int idx = 0; idx < (1 << z); idx++)
        {
            adrs.setType(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(s + idx);
            byte[] node = wots.pkGen(skSeed, pkSeed, adrs);

            adrs.setType(ADRS.TREE);
            adrs.setTreeHeight(1);
            adrs.setTreeIndex(s + idx);

            // while ( Top node on Stack has same height as node )
            while (!stack.isEmpty()
                && ((NodeEntry)stack.get(0)).nodeHeight == adrs.getTreeHeight())
            {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                NodeEntry current = ((NodeEntry)stack.remove(0));

                node = engine.H(pkSeed, adrs, current.nodeValue, node);
                //topmost node is now one layer higher
                adrs.setTreeHeight(adrs.getTreeHeight() + 1);
            }

            stack.add(0, new NodeEntry(node, adrs.getTreeHeight()));
        }
 
        return ((NodeEntry)stack.get(0)).nodeValue;
    }

    //    # Input: Message M, signature SIG_HT, public seed PK.seed, tree index idx_tree,
//    leaf index idx_leaf, HT public key PK_HT.
//    # Output: Boolean
    public boolean verify(byte[] M, SIG_XMSS[] sig_ht, byte[] pkSeed, long idx_tree, int idx_leaf, byte[] PK_HT)
    {
        // init
        ADRS adrs = new ADRS();
        // verify
        SIG_XMSS SIG_tmp = sig_ht[0];
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        byte[] node = xmss_pkFromSig(idx_leaf, SIG_tmp, M, pkSeed, adrs);
        for (int j = 1; j < engine.D; j++)
        {
            idx_leaf = (int)(idx_tree & ((1 << engine.H_PRIME) - 1));  // least significant bits of idx_tree;
            idx_tree >>>= engine.H_PRIME; // most significant bits of idx_tree;
            SIG_tmp = sig_ht[j];
            adrs.setLayerAddress(j);
            adrs.setTreeAddress(idx_tree);
            node = xmss_pkFromSig(idx_leaf, SIG_tmp, node, pkSeed, adrs);
        }
        return Arrays.areEqual(PK_HT, node);
    }
}
