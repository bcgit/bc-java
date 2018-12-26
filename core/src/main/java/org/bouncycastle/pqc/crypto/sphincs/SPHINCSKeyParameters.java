package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SPHINCSKeyParameters
    extends AsymmetricKeyParameter
{
    /**
     * Use SHA512-256 for the tree generation function.
     */
    public static final String SHA512_256 = "SHA-512/256";

    /**
     * Use SHA3-256 for the tree generation function.
     */
    public static final String SHA3_256 = "SHA3-256";

    private final String treeDigest;

    protected SPHINCSKeyParameters(boolean isPrivateKey, String treeDigest)
    {
        super(isPrivateKey);
        this.treeDigest = treeDigest;
    }

    public String getTreeDigest()
    {
        return treeDigest;
    }
}
