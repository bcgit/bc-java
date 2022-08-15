package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

public class DilithiumParameters
{
    public static final DilithiumParameters dilithium2 = new DilithiumParameters("dilithium2", 2);
    public static final DilithiumParameters dilithium3 = new DilithiumParameters("dilithium3", 3);
    public static final DilithiumParameters dilithium5 = new DilithiumParameters("dilithium5", 5);

    private final int k;
    private final String name;

    private DilithiumParameters(String name, int k)
    {
        this.name = name;
        this.k = k;
    }

    DilithiumEngine getEngine(SecureRandom random)
    {
        return new DilithiumEngine(k, random);
    }

    public String getName()
    {
        return name;
    }
}
