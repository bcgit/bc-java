package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.pqc.crypto.KEMParameters;

public class SABERParameters
    implements KEMParameters
{

    public static final SABERParameters lightsaberkem128r3 = new SABERParameters("lightsaberkem128r3", 2, 128, false, false);
    public static final SABERParameters saberkem128r3 = new SABERParameters("saberkem128r3", 3, 128, false, false);
    public static final SABERParameters firesaberkem128r3 = new SABERParameters("firesaberkem128r3", 4, 128, false, false);

    public static final SABERParameters lightsaberkem192r3 = new SABERParameters("lightsaberkem192r3", 2, 192, false, false);
    public static final SABERParameters saberkem192r3 = new SABERParameters("saberkem192r3", 3, 192, false, false);
    public static final SABERParameters firesaberkem192r3 = new SABERParameters("firesaberkem192r3", 4, 192, false, false);

    public static final SABERParameters lightsaberkem256r3 = new SABERParameters("lightsaberkem256r3", 2, 256, false, false);
    public static final SABERParameters saberkem256r3 = new SABERParameters("saberkem256r3", 3, 256, false, false);
    public static final SABERParameters firesaberkem256r3 = new SABERParameters("firesaberkem256r3", 4, 256, false, false);


    public static final SABERParameters lightsaberkem90sr3 = new SABERParameters("lightsaberkem90sr3", 2, 256, true, false);
    public static final SABERParameters saberkem90sr3 = new SABERParameters("saberkem90sr3", 3, 256, true, false);
    public static final SABERParameters firesaberkem90sr3 = new SABERParameters("firesaberkem90sr3", 4, 256, true, false);

    public static final SABERParameters ulightsaberkemr3 = new SABERParameters("ulightsaberkemr3", 2, 256, false, true);
    public static final SABERParameters usaberkemr3 = new SABERParameters("usaberkemr3", 3, 256, false, true);
    public static final SABERParameters ufiresaberkemr3 = new SABERParameters("ufiresaberkemr3", 4, 256, false, true);

    public static final SABERParameters ulightsaberkem90sr3 = new SABERParameters("ulightsaberkem90sr3", 2, 256, true, true);
    public static final SABERParameters usaberkem90sr3 = new SABERParameters("usaberkem90sr3", 3, 256, true, true);
    public static final SABERParameters ufiresaberkem90sr3 = new SABERParameters("ufiresaberkem90sr3", 4, 256, true, true);

    private final String name;
    private final int l;
    private final int defaultKeySize;
    private final SABEREngine engine;

    public SABERParameters(String name, int l, int defaultKeySize, boolean usingAes, boolean usingEffectiveMasking)
    {
        this.name = name;
        this.l = l;
        this.defaultKeySize = defaultKeySize;
        this.engine = new SABEREngine(l, defaultKeySize, usingAes, usingEffectiveMasking);
    }

    public String getName()
    {
        return name;
    }

    public int getL()
    {
        return l;
    }

    public int getSessionKeySize()
    {
        return defaultKeySize;
    }

    public SABEREngine getEngine()
    {
        return engine;
    }
}
