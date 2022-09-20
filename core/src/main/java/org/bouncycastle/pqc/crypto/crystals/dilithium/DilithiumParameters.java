package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

public class DilithiumParameters
{
    public static final DilithiumParameters dilithium2 = new DilithiumParameters("dilithium2", 2, false);
    public static final DilithiumParameters dilithium2_aes = new DilithiumParameters("dilithium2-aes", 2, true);

    public static final DilithiumParameters dilithium3 = new DilithiumParameters("dilithium3", 3, false);
    public static final DilithiumParameters dilithium3_aes = new DilithiumParameters("dilithium3-aes", 3, true);

    public static final DilithiumParameters dilithium5 = new DilithiumParameters("dilithium5", 5, false);
    public static final DilithiumParameters dilithium5_aes = new DilithiumParameters("dilithium5-aes", 5, true);

    private final int k;
    private final String name;

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
