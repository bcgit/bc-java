package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

public class DilithiumParameters
{
    public static final DilithiumParameters dilithium2 = new DilithiumParameters("dilithium2", 2, false);
    public static final DilithiumParameters dilithium3 = new DilithiumParameters("dilithium3", 3, false);
    public static final DilithiumParameters dilithium5 = new DilithiumParameters("dilithium5", 5, false);

    private final int k;
    private final String name;

    /**
     * @deprecated
     * obsolete to be removed
     */
    @Deprecated
    private final boolean usingAES;// or shake

    private DilithiumParameters(String name, int k, boolean usingAES)
    {
        this.name = name;
        this.k = k;
        this.usingAES = usingAES;
    }

    DilithiumEngine getEngine(SecureRandom random)
    {
        return new DilithiumEngine(k, random, usingAES);
    }

    public String getName()
    {
        return name;
    }
}
