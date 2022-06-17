package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.LinkedList;

import org.bouncycastle.util.Arrays;

class Fors
{
    SPHINCSPlusEngine engine;

    public Fors(SPHINCSPlusEngine engine)
    {
        this.engine = engine;
    }

    // Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
    // Output: n-byte root node - top node on Stack
    byte[] treehash(byte[] skSeed, int s, int z, byte[] pkSeed, ADRS adrsParam)
    {
        LinkedList<NodeEntry> stack = new LinkedList<NodeEntry>();

        if (s % (1 << z) != 0)
        {
            return null;
        }

        ADRS adrs = new ADRS(adrsParam);

        for (int idx = 0; idx < (1 << z); idx++)
        {
            adrs.setType(ADRS.FORS_PRF);
            adrs.setKeyPairAddress(adrsParam.getKeyPairAddress());
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(s + idx);

            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);

            adrs.changeType(ADRS.FORS_TREE);

            byte[] node = engine.F(pkSeed, adrs, sk);

            adrs.setTreeHeight(1);

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

    public SIG_FORS[] sign(byte[] md, byte[] skSeed, byte[] pkSeed, ADRS paramAdrs)
    {
        ADRS adrs = new ADRS(paramAdrs);

        int[] idxs = message_to_idxs(md, engine.K, engine.A);
        SIG_FORS[] sig_fors = new SIG_FORS[engine.K];
// compute signature elements
        int t = engine.T;
        for (int i = 0; i < engine.K; i++)
        {
// get next index
            int idx = idxs[i];
// pick private key element
            adrs.setType(ADRS.FORS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(i * t + idx);

            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);

            adrs.changeType(ADRS.FORS_TREE);

            byte[][] authPath = new byte[engine.A][];
// compute auth path
            for (int j = 0; j < engine.A; j++)
            {
                int s = (idx / (1 << j)) ^ 1;
                authPath[j] = treehash(skSeed, i * t + s * (1 << j), j, pkSeed, adrs);
            }
            sig_fors[i] = new SIG_FORS(sk, authPath);
        }
        return sig_fors;
    }

    public byte[] pkFromSig(SIG_FORS[] sig_fors, byte[] message, byte[] pkSeed, ADRS adrs)
    {
        byte[][] node = new byte[2][];
        byte[][] root = new byte[engine.K][];
        int t = engine.T;

        int[] idxs = message_to_idxs(message, engine.K, engine.A);
        // compute roots
        for (int i = 0; i < engine.K; i++)
        {
            // get next index
            int idx = idxs[i];
            // compute leaf
            byte[] sk = sig_fors[i].getSK();
            adrs.setTreeHeight(0);
            adrs.setTreeIndex(i * t + idx);
            node[0] = engine.F(pkSeed, adrs, sk);
            // compute root from leaf and AUTH
            byte[][] authPath = sig_fors[i].getAuthPath();

            adrs.setTreeIndex(i * t + idx);
            for (int j = 0; j < engine.A; j++)
            {
                adrs.setTreeHeight(j + 1);
                if (((idx / (1 << j)) % 2) == 0)
                {
                    adrs.setTreeIndex(adrs.getTreeIndex() / 2);
                    node[1] = engine.H(pkSeed, adrs, node[0], authPath[j]);
                }
                else
                {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
                    node[1] = engine.H(pkSeed, adrs, authPath[j], node[0]);
                }
                node[0] = node[1];
            }
            root[i] = node[0];
        }
        ADRS forspkADRS = new ADRS(adrs); // copy address to create FTS public key address
        forspkADRS.setType(ADRS.FORS_PK);
        forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress());
        return engine.T_l(pkSeed, forspkADRS, Arrays.concatenate(root));
    }

    /**
     * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
     * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
     * Assumes indices has space for SPX_FORS_TREES integers.
     */
    static int[] message_to_idxs(byte[] msg, int fors_trees, int fors_height)
    {
        int offset = 0;
        int[] idxs = new int[fors_trees];
        for (int i = 0; i < fors_trees; i++)
        {
            idxs[i] = 0;
            for (int j = 0; j < fors_height; j++)
            {
                idxs[i] ^= ((msg[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
                offset++;
            }
        }
        return idxs;
    }
}
