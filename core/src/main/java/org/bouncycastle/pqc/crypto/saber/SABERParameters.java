package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.crypto.CipherParameters;

public class SABERParameters
    implements CipherParameters
{

    public static final SABERParameters lightsaberkemr3 = new SABERParameters("lightsaberkemr3", 2, 32);
    public static final SABERParameters saberkemr3 = new SABERParameters("saberkemr3", 3, 32);
    public static final SABERParameters firesaberkemr3 = new SABERParameters("firesaberkemr3", 4, 32);

    private final String name;
    private final int l;
    private final int defaultKeySize;
    private final SABEREngine engine;

    public SABERParameters(String name, int l, int defaultKeySize)
    {
        this.name = name;
        this.l = l;
        this.defaultKeySize = defaultKeySize;
        this.engine = new SABEREngine(l);
    }

    public String getName()
    {
        return name;
    }

    public int getL()
    {
        return l;
    }

    public int getDefaultKeySize()
    {
        return defaultKeySize;
    }

    public SABEREngine getEngine()
    {
        return engine;
    }
}
