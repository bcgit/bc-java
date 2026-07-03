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

    /**
     * Use SHA-256/192 (SHA-256 truncated to 192 bits) for the tree generation function (SP 800-208).
     */
    public static final String SHA256_192 = "SHA256/192";

    /**
     * Use SHAKE256/256 (SHAKE256 with a 256-bit output) for the tree generation function (SP 800-208).
     */
    public static final String SHAKE256_256 = "SHAKE256/256";

    /**
     * Use SHAKE256/192 (SHAKE256 with a 192-bit output) for the tree generation function (SP 800-208).
     */
    public static final String SHAKE256_192 = "SHAKE256/192";

    public static final XMSSMTParameterSpec XMSSMT_SHA2_20d2_256 = new XMSSMTParameterSpec(20, 2, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_20d4_256 = new XMSSMTParameterSpec(20, 4, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d2_256 = new XMSSMTParameterSpec(40, 2, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d4_256 = new XMSSMTParameterSpec(40, 4, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d8_256 = new XMSSMTParameterSpec(40, 8, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d3_256 = new XMSSMTParameterSpec(60, 3, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d6_256 = new XMSSMTParameterSpec(60, 6, SHA256);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d12_256 = new XMSSMTParameterSpec(60, 12, SHA256);

    public static final XMSSMTParameterSpec XMSSMT_SHA2_20d2_512 = new XMSSMTParameterSpec(20, 2, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_20d4_512 = new XMSSMTParameterSpec(20, 4, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d2_512 = new XMSSMTParameterSpec(40, 2, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d4_512 = new XMSSMTParameterSpec(40, 4, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d8_512 = new XMSSMTParameterSpec(40, 8, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d3_512 = new XMSSMTParameterSpec(60, 3, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d6_512 = new XMSSMTParameterSpec(60, 6, SHA512);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d12_512 = new XMSSMTParameterSpec(60, 12, SHA512);

    public static final XMSSMTParameterSpec XMSSMT_SHAKE_20d2_256 = new XMSSMTParameterSpec(20, 2, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_20d4_256 = new XMSSMTParameterSpec(20, 4, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_40d2_256 = new XMSSMTParameterSpec(40, 2, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_40d4_256 = new XMSSMTParameterSpec(40, 4, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_40d8_256 = new XMSSMTParameterSpec(40, 8, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_60d3_256 = new XMSSMTParameterSpec(60, 3, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_60d6_256 = new XMSSMTParameterSpec(60, 6, SHAKE128);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_60d12_256 = new XMSSMTParameterSpec(60, 12, SHAKE128);

    public static final XMSSMTParameterSpec XMSSMT_SHAKE_20d2_512 = new XMSSMTParameterSpec(20, 2, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_20d4_512 = new XMSSMTParameterSpec(20, 4, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_40d2_512 = new XMSSMTParameterSpec(40, 2, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_40d4_512 = new XMSSMTParameterSpec(40, 4, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_40d8_512 = new XMSSMTParameterSpec(40, 8, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_60d3_512 = new XMSSMTParameterSpec(60, 3, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_60d6_512 = new XMSSMTParameterSpec(60, 6, SHAKE256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE_60d12_512 = new XMSSMTParameterSpec(60, 12, SHAKE256);

    // SP 800-208 XMSS^MT parameters (SHA-256/192, SHAKE256/256, SHAKE256/192)
    public static final XMSSMTParameterSpec XMSSMT_SHA2_20d2_192 = new XMSSMTParameterSpec(20, 2, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_20d4_192 = new XMSSMTParameterSpec(20, 4, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d2_192 = new XMSSMTParameterSpec(40, 2, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d4_192 = new XMSSMTParameterSpec(40, 4, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_40d8_192 = new XMSSMTParameterSpec(40, 8, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d3_192 = new XMSSMTParameterSpec(60, 3, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d6_192 = new XMSSMTParameterSpec(60, 6, SHA256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHA2_60d12_192 = new XMSSMTParameterSpec(60, 12, SHA256_192);

    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_20d2_256 = new XMSSMTParameterSpec(20, 2, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_20d4_256 = new XMSSMTParameterSpec(20, 4, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_40d2_256 = new XMSSMTParameterSpec(40, 2, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_40d4_256 = new XMSSMTParameterSpec(40, 4, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_40d8_256 = new XMSSMTParameterSpec(40, 8, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_60d3_256 = new XMSSMTParameterSpec(60, 3, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_60d6_256 = new XMSSMTParameterSpec(60, 6, SHAKE256_256);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_60d12_256 = new XMSSMTParameterSpec(60, 12, SHAKE256_256);

    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_20d2_192 = new XMSSMTParameterSpec(20, 2, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_20d4_192 = new XMSSMTParameterSpec(20, 4, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_40d2_192 = new XMSSMTParameterSpec(40, 2, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_40d4_192 = new XMSSMTParameterSpec(40, 4, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_40d8_192 = new XMSSMTParameterSpec(40, 8, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_60d3_192 = new XMSSMTParameterSpec(60, 3, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_60d6_192 = new XMSSMTParameterSpec(60, 6, SHAKE256_192);
    public static final XMSSMTParameterSpec XMSSMT_SHAKE256_60d12_192 = new XMSSMTParameterSpec(60, 12, SHAKE256_192);

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
