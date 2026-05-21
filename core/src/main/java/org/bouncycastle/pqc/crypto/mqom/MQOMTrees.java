package org.bouncycastle.pqc.crypto.mqom;

/**
 * GGM-tree helpers for MQOM v2.1. Trees are represented as a flat node array
 * of size <code>FULL_TREE_SIZE + 1</code>; index 0 is unused (the "skipped root"),
 * the level-1 children are at positions 2 and 3 (with
 * <code>node[3] = node[2] XOR delta</code>) and leaves are
 * <code>node[N..2N-1]</code>.
 *
 * <p>The PartiallyExpand variant — used by the verifier — re-derives all leaves
 * except <code>lseed[i_star]</code> (which is returned as zero) from the
 * sibling path.
 *
 * <p>Instances are not thread-safe — scratch buffers are reused across calls.
 */
final class MQOMTrees
{
    private final MQOMSymmetric sym;
    private final int seedSize;
    private final int saltSize;
    private final int nbEvalsLog;
    private final int nbEvals;

    /* Scratch — sized at construction. */
    private final byte[] scratchTweakedSalt;    // saltSize
    private final byte[][] scratchPartialNode;  // [fullTreeSize+1][seedSize]
    private final boolean[] scratchPartialMap;  // [fullTreeSize+1]

    MQOMTrees(MQOMSymmetric sym)
    {
        this.sym = sym;
        this.seedSize = sym.getSeedSize();
        this.saltSize = sym.getSaltSize();
        this.nbEvalsLog = sym.getParameters().getNbEvalsLog();
        this.nbEvals = sym.getParameters().getNbEvals();

        this.scratchTweakedSalt = new byte[saltSize];
        int fullTreeSize = sym.getParameters().getFullTreeSize();
        this.scratchPartialNode = new byte[fullTreeSize + 1][seedSize];
        this.scratchPartialMap = new boolean[fullTreeSize + 1];
    }

    /**
     * Expand the GGM tree for execution e, given salt, root seed and offset delta.
     * <code>node</code> is a 2D buffer of shape [FULL_TREE_SIZE + 1][seedSize].
     * <code>lseed</code> is a 2D buffer of shape [nbEvals][seedSize] receiving
     * the leaves.
     */
    void expand(byte[] salt,
                byte[] rseed, int rseedOff,
                byte[] delta, int deltaOff,
                int e,
                byte[][] node,
                byte[][] lseed)
    {
        System.arraycopy(rseed, rseedOff, node[2], 0, seedSize);
        for (int i = 0; i < seedSize; i++)
        {
            node[3][i] = (byte)((node[2][i] ^ delta[deltaOff + i]) & 0xFF);
        }

        byte[] tweakedSalt = scratchTweakedSalt;
        for (int j = 1; j < nbEvalsLog; j++)
        {
            sym.tweakSalt(salt, tweakedSalt, 2, e, j - 1);
            Object ctx = sym.encKeySched(tweakedSalt, 0);
            int start = 1 << j;
            int end = 1 << (j + 1);
            for (int k = start; k < end; k++)
            {
                sym.seedDerive(ctx, node[k], 0, node[2 * k], 0);
                for (int b = 0; b < seedSize; b++)
                {
                    node[2 * k + 1][b] = (byte)((node[2 * k][b] ^ node[k][b]) & 0xFF);
                }
            }
        }

        for (int i = 0; i < nbEvals; i++)
        {
            System.arraycopy(node[nbEvals + i], 0, lseed[i], 0, seedSize);
        }
    }

    /**
     * Extract the sibling path for the hidden leaf index <code>iStar</code> from
     * a fully-expanded tree.
     */
    void open(byte[][] node, int iStar, byte[][] path)
    {
        int idx = nbEvals + iStar;
        for (int j = 0; j < nbEvalsLog; j++)
        {
            System.arraycopy(node[idx ^ 1], 0, path[j], 0, seedSize);
            idx >>>= 1;
        }
    }

    /**
     * Re-derive all leaves except <code>lseed[iStar]</code> from the sibling
     * path. <code>lseed[iStar]</code> is set to zero on return.
     */
    void partiallyExpand(byte[] salt,
                         byte[][] path,
                         int e,
                         int iStar,
                         byte[][] lseed)
    {
        byte[][] node = scratchPartialNode;
        boolean[] nodeMap = scratchPartialMap;
        for (int i = 0; i < nodeMap.length; i++)
        {
            nodeMap[i] = false;
        }

        int idx = nbEvals + iStar;
        for (int j = 0; j < nbEvalsLog; j++)
        {
            int sibling = idx ^ 1;
            System.arraycopy(path[j], 0, node[sibling], 0, seedSize);
            nodeMap[sibling] = true;
            idx >>>= 1;
        }

        byte[] tweakedSalt = scratchTweakedSalt;
        for (int j = 1; j < nbEvalsLog; j++)
        {
            sym.tweakSalt(salt, tweakedSalt, 2, e, j - 1);
            Object ctx = sym.encKeySched(tweakedSalt, 0);
            int start = 1 << j;
            int end = 1 << (j + 1);
            for (int k = start; k < end; k++)
            {
                if (!nodeMap[k])
                {
                    continue;
                }
                sym.seedDerive(ctx, node[k], 0, node[2 * k], 0);
                for (int b = 0; b < seedSize; b++)
                {
                    node[2 * k + 1][b] = (byte)((node[2 * k][b] ^ node[k][b]) & 0xFF);
                }
                nodeMap[2 * k] = true;
                nodeMap[2 * k + 1] = true;
            }
        }

        for (int i = 0; i < nbEvals; i++)
        {
            System.arraycopy(node[nbEvals + i], 0, lseed[i], 0, seedSize);
        }
        for (int b = 0; b < seedSize; b++)
        {
            lseed[iStar][b] = 0;
        }
    }
}
