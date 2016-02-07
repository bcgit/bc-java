package org.bouncycastle.pqc.jcajce.spec;

/**
 * Key generation spec for SPHINCS-256 to allow specifying of tree hash.
 */
public class SPHINCS256KeyGenParameterSpec
{
    /**
     * Use SHA512-256 for the tree generation function.
     */
    public static final String SHA512_256 = "SHA512-256";

    /**
     * Use SHA3-256 for the tree generation function.
     */
    public static final String SHA3_256 = "SHA3-256";

    private final String treeHash;

    /**
     * Specify the treehash, one of SHA512-256, or SHA3-256.
     *
     * @param treeHash the hash for building the public key tree.
     */
    public SPHINCS256KeyGenParameterSpec(String treeHash)
    {
        this.treeHash = treeHash;
    }
}
