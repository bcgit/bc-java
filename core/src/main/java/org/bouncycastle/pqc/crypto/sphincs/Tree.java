package org.bouncycastle.pqc.crypto.sphincs;

class Tree
{
    static class leafaddr
    {
        int level;
        long subtree;
        long subleaf;

        public leafaddr()
        {

        }

        public leafaddr(leafaddr leafaddr)
        {
            this.level = leafaddr.level;
            this.subtree = leafaddr.subtree;
            this.subleaf = leafaddr.subleaf;
        }
    }

    static void l_tree(HashFunctions hs, byte[] leaf, int leafOff, byte[] wots_pk, int pkOff, byte[] masks, int masksOff)
    {
        int l = Wots.WOTS_L;
        int i, j = 0;
        for (i = 0; i < Wots.WOTS_LOG_L; i++)
        {
            for (j = 0; j < (l >>> 1); j++)
            {
                hs.hash_2n_n_mask(wots_pk, pkOff + j * SPHINCS256Config.HASH_BYTES, wots_pk, pkOff + j * 2 * SPHINCS256Config.HASH_BYTES, masks, masksOff + i * 2 * SPHINCS256Config.HASH_BYTES);
            }

            if ((l & 1) != 0)
            {
                System.arraycopy(wots_pk, pkOff + (l - 1) * SPHINCS256Config.HASH_BYTES, wots_pk, pkOff + (l >>> 1) * SPHINCS256Config.HASH_BYTES, SPHINCS256Config.HASH_BYTES);
                l = (l >>> 1) + 1;
            }
            else
            {
                l = (l >>> 1);
            }
        }
        System.arraycopy(wots_pk, pkOff, leaf, leafOff, SPHINCS256Config.HASH_BYTES);
    }

    static void treehash(HashFunctions hs, byte[] node, int nodeOff, int height, byte[] sk, leafaddr leaf, byte[] masks, int masksOff)
    {
        leafaddr a = new leafaddr(leaf);
        int lastnode, i;
        byte[] stack = new byte[(height + 1) * SPHINCS256Config.HASH_BYTES];
        int[] stacklevels = new int[height + 1];
        int stackoffset = 0;

        lastnode = (int)(a.subleaf + (1 << height));

        for (; a.subleaf < lastnode; a.subleaf++)
        {
            gen_leaf_wots(hs, stack, stackoffset * SPHINCS256Config.HASH_BYTES, masks, masksOff, sk, a);
            stacklevels[stackoffset] = 0;
            stackoffset++;
            while (stackoffset > 1 && stacklevels[stackoffset - 1] == stacklevels[stackoffset - 2])
            {
                //MASKS
                int maskoffset = 2 * (stacklevels[stackoffset - 1] + Wots.WOTS_LOG_L) * SPHINCS256Config.HASH_BYTES;

                hs.hash_2n_n_mask(stack, (stackoffset - 2) * SPHINCS256Config.HASH_BYTES, stack, (stackoffset - 2) * SPHINCS256Config.HASH_BYTES,
                    masks, masksOff + maskoffset);
                stacklevels[stackoffset - 2]++;
                stackoffset--;
            }
        }
        for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
        {
            node[nodeOff + i] = stack[i];
        }
    }

    static void gen_leaf_wots(HashFunctions hs, byte[] leaf, int leafOff, byte[] masks, int masksOff, byte[] sk, leafaddr a)
    {
        byte[] seed = new byte[SPHINCS256Config.SEED_BYTES];
        byte[] pk = new byte[Wots.WOTS_L * SPHINCS256Config.HASH_BYTES];

        Wots w = new Wots();

        Seed.get_seed(hs, seed, 0, sk, a);

        w.wots_pkgen(hs, pk, 0, seed, 0, masks, masksOff);

        l_tree(hs, leaf, leafOff, pk, 0, masks, masksOff);
    }
}
