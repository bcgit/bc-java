package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class XMSSParameterSpec
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

    /**
     * Standard XMSS parameters
     */
    public static final XMSSParameterSpec SHA2_10_256 = new XMSSParameterSpec(10, SHA256);
    public static final XMSSParameterSpec SHA2_16_256 = new XMSSParameterSpec(16, SHA256);
    public static final XMSSParameterSpec SHA2_20_256 = new XMSSParameterSpec(20, SHA256);
    public static final XMSSParameterSpec SHAKE_10_256 = new XMSSParameterSpec(10, SHAKE128);
    public static final XMSSParameterSpec SHAKE_16_256 = new XMSSParameterSpec(16, SHAKE128);
    public static final XMSSParameterSpec SHAKE_20_256 = new XMSSParameterSpec(20, SHAKE128);

    public static final XMSSParameterSpec SHA2_10_512 = new XMSSParameterSpec(10, SHA512);
    public static final XMSSParameterSpec SHA2_16_512 = new XMSSParameterSpec(16, SHA512);
    public static final XMSSParameterSpec SHA2_20_512 = new XMSSParameterSpec(20, SHA512);
    public static final XMSSParameterSpec SHAKE_10_512 = new XMSSParameterSpec(10, SHAKE256);
    public static final XMSSParameterSpec SHAKE_16_512 = new XMSSParameterSpec(16, SHAKE256);
    public static final XMSSParameterSpec SHAKE_20_512 = new XMSSParameterSpec(20, SHAKE256);

    /**
     * SP 800-208 XMSS parameters (SHA-256/192, SHAKE256/256, SHAKE256/192)
     */
    public static final XMSSParameterSpec SHA2_10_192 = new XMSSParameterSpec(10, SHA256_192);
    public static final XMSSParameterSpec SHA2_16_192 = new XMSSParameterSpec(16, SHA256_192);
    public static final XMSSParameterSpec SHA2_20_192 = new XMSSParameterSpec(20, SHA256_192);

    public static final XMSSParameterSpec SHAKE256_10_256 = new XMSSParameterSpec(10, SHAKE256_256);
    public static final XMSSParameterSpec SHAKE256_16_256 = new XMSSParameterSpec(16, SHAKE256_256);
    public static final XMSSParameterSpec SHAKE256_20_256 = new XMSSParameterSpec(20, SHAKE256_256);

    public static final XMSSParameterSpec SHAKE256_10_192 = new XMSSParameterSpec(10, SHAKE256_192);
    public static final XMSSParameterSpec SHAKE256_16_192 = new XMSSParameterSpec(16, SHAKE256_192);
    public static final XMSSParameterSpec SHAKE256_20_192 = new XMSSParameterSpec(20, SHAKE256_192);

    private final int height;
    private final String treeDigest;

    public XMSSParameterSpec(int height, String treeDigest)
    {
        this.height = height;
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
}
