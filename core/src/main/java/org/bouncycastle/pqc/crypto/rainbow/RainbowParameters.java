package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

public class RainbowParameters
    implements CipherParameters
{
    public static final RainbowParameters rainbowIIIclassic = new RainbowParameters("rainbow-III-classic", 3, Version.CLASSIC);
    public static final RainbowParameters rainbowIIIcircumzenithal = new RainbowParameters("rainbow-III-circumzenithal", 3, Version.CIRCUMZENITHAL);
    public static final RainbowParameters rainbowIIIcompressed = new RainbowParameters("rainbow-III-compressed", 3, Version.COMPRESSED);

    public static final RainbowParameters rainbowVclassic = new RainbowParameters("rainbow-V-classic", 5, Version.CLASSIC);
    public static final RainbowParameters rainbowVcircumzenithal = new RainbowParameters("rainbow-V-circumzenithal", 5, Version.CIRCUMZENITHAL);
    public static final RainbowParameters rainbowVcompressed = new RainbowParameters("rainbow-V-compressed", 5, Version.COMPRESSED);

    private final int v1;
    private final int v2;
    private final int o1;
    private final int o2;
    private final int n;
    private final int m;
    private static final int len_pkseed = 32;
    private static final int len_skseed = 32;
    private static final int len_salt = 16;
    private final Digest hash_algo;
    private final Version version;
    private final String name;

    private RainbowParameters(String name, int strength, Version version)
    {
        this.name = name;

        switch (strength)
        {
        case 3:
            this.v1 = 68;
            this.o1 = 32;
            this.o2 = 48;
            this.hash_algo = new SHA384Digest();
            break;
        case 5:
            this.v1 = 96;
            this.o1 = 36;
            this.o2 = 64;
            this.hash_algo = new SHA512Digest();
            break;
        default:
            throw new IllegalArgumentException(
                "No valid version. Please choose one of the following: 3, 5");
        }

        this.v2 = v1 + o1;
        this.n = v1 + o1 + o2;
        this.m = o1 + o2;
        this.version = version;
    }

    public String getName()
    {
        return name;
    }

    Version getVersion()
    {
        return this.version;
    }

    int getV1()
    {
        return this.v1;
    }

    int getO1()
    {
        return this.o1;
    }

    int getO2()
    {
        return this.o2;
    }

    Digest getHash_algo()
    {
        return this.hash_algo;
    }

    int getV2()
    {
        return v2;
    }

    int getN()
    {
        return n;
    }

    int getM()
    {
        return m;
    }

    int getLen_pkseed()
    {
        return len_pkseed;
    }

    int getLen_skseed()
    {
        return len_skseed;
    }

    int getLen_salt()
    {
        return len_salt;
    }

}
