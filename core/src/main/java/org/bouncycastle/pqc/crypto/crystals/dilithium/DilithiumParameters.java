package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

public class DilithiumParameters
{
    public static final DilithiumParameters dilithium2 = new DilithiumParameters(2);
    public static final DilithiumParameters dilithium3 = new DilithiumParameters(3);
    public static final DilithiumParameters dilithium5 = new DilithiumParameters(5);

    private final int k;

    private DilithiumParameters(int k)
    {
        this.k = k;
    }

    DilithiumEngine getEngine(SecureRandom random)
    {
        return new DilithiumEngine(k, random);
    }
}
