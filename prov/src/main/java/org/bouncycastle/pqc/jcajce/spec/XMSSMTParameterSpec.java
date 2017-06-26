package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class XMSSMTParameterSpec
    implements AlgorithmParameterSpec
{
    /**
     * Use SHA-256 for the tree generation function.
     */
    public static final String SHA256 = "SHA256";

    /**
     * Use SHA512 for the tree generation function.
     */
    public static final String SHA512 = "SHA512";

    /**
     * Use SHAKE128 for the tree generation function.
     */
    public static final String SHAKE128 = "SHAKE128";

    /**
     * Use SHAKE256 for the tree generation function.
     */
    public static final String SHAKE256 = "SHAKE256";

    private final int height;
    private final int layers;
    private final String treeDigest;

    public XMSSMTParameterSpec(int height, int layers, String treeDigest)
    {
        this.height = height;
        this.layers = layers;
        this.treeDigest = treeDigest;
    }

    public String getTreeDigest()
    {
        return treeDigest;
    }

    public int getHeight()
    {
        return height;
    }

    public int getLayers()
    {
        return layers;
    }
}
