package org.bouncycastle.openpgp.wot;

/**
 * Configuration settings for the trust calculation.
 */
public class Config implements TrustConst
{
    public static final int TM_CLASSIC = 0;
    public static final int TM_PGP = 1;
    public static final int TM_EXTERNAL = 2;
    public static final int TM_ALWAYS = 3;
    public static final int TM_DIRECT = 4;

    private static final Config instance = new Config();

    protected Config()
    {
    }

    public static Config getInstance()
    {
        return instance;
    }

    public short getMarginalsNeeded()
    {
        return 3;
    }

    public short getCompletesNeeded()
    {
        return 1;
    }

    public short getMaxCertDepth()
    {
        return 5;
    }

    public short getTrustModel()
    {
        return TM_PGP; // This must never be anything else! We support only
                       // TM_PGP = 1!!!
    }

    public short getMinCertLevel()
    {
        return 2;
    }

    public String getTrustModelAsString()
    {
        switch (getTrustModel())
        {
            case TM_CLASSIC:
                return "classic";
            case TM_PGP:
                return "PGP";
            case TM_EXTERNAL:
                return "external";
            case TM_ALWAYS:
                return "always";
            case TM_DIRECT:
                return "direct";
            default:
                return "unknown[" + getTrustModel() + "]";
        }
    }
}
