package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.util.Pack;

/**
 * Tree-PRG used by SDitH-Hypercube to expand a root seed into a full binary
 * tree of seeds (see reference treeprg.c). Each child seed is derived as
 * <pre>
 *     out[i] = SHA3(prefix=HASH_TREE || salt || iteration_le16 || node_idx_le16 || parent_seed)
 * </pre>
 * truncated to seed_size bytes. The leaf-expand path expands a leaf seed plus
 * salt into (out_seed, out_rho); both are PARAM_seed_size bytes.
 */
final class SDitHTreePrg
{
    private final int hashBits;
    private final int seedSize;
    private final byte[] salt;

    SDitHTreePrg(int hashBits, int seedSize, byte[] salt)
    {
        this.hashBits = hashBits;
        this.seedSize = seedSize;
        this.salt = salt;
    }

    /**
     * Expands n/2 input seeds into n output seeds. Each SHA3 call emits
     * 2 * seedSize bytes (= the SHA3 digest size for the parameter set);
     * those bytes are the two children of the input seed at the same index.
     */
    void seedExpand(byte[] outLevel, int outOff, byte[] inLevel, int inOff, int firstTweak, int iteration, int n)
    {
        if ((n & 1) != 0)
        {
            throw new IllegalArgumentException("n must be even");
        }
        int tweak = firstTweak;
        byte[] vec = new byte[salt.length + 2 + 2 + seedSize];
        System.arraycopy(salt, 0, vec, 0, salt.length);
        Pack.shortToLittleEndian((short)iteration, vec, salt.length);
        for (int i = 0; i < n / 2; ++i)
        {
            Pack.shortToLittleEndian((short)tweak, vec, salt.length + 2);
            System.arraycopy(inLevel, inOff + i * seedSize, vec, salt.length + 4, seedSize);
            byte[] hash = new byte[hashBits / 8];
            SDitHHash.oneShot(hashBits, SDitHHash.HASH_TREE, vec, 0, vec.length, hash, 0);
            System.arraycopy(hash, 0, outLevel, outOff + (2 * i) * seedSize, 2 * seedSize);
            ++tweak;
        }
    }

    /**
     * Expand a leaf seed into (out_seed || out_rho). Matches sdith_tree_prg_leaf_expand.
     * Not used by the hypercube cat1 sign path (which absorbs leaves directly via
     * the engine's commitLeaf), but the reference exposes it so we keep it.
     */
    void leafExpand(byte[] inSeed, int inSeedOff, byte[] outSeed, int outSeedOff, byte[] outRho, int outRhoOff,
                    int rhoSize)
    {
        byte[] in = new byte[seedSize + salt.length];
        System.arraycopy(inSeed, inSeedOff, in, 0, seedSize);
        System.arraycopy(salt, 0, in, seedSize, salt.length);
        byte[] out = new byte[seedSize + rhoSize];
        SDitHHash.oneShot(hashBits, SDitHHash.HASH_TREE, in, 0, in.length, out, 0);
        System.arraycopy(out, 0, outSeed, outSeedOff, seedSize);
        System.arraycopy(out, seedSize, outRho, outRhoOff, rhoSize);
    }
}
