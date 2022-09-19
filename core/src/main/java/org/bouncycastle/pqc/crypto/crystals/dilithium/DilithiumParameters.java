package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

public class DilithiumParameters
{
    public static final DilithiumParameters dilithium2 = new DilithiumParameters("dilithium2shake", 2, false, false);
    public static final DilithiumParameters dilithium2R = new DilithiumParameters("dilithium2shakeR", 2, true, false);
    public static final DilithiumParameters dilithium2aes = new DilithiumParameters("dilithium2aes", 2, false, true);
    public static final DilithiumParameters dilithium2aesR = new DilithiumParameters("dilithium2aesR", 2, true, true);

    public static final DilithiumParameters dilithium3 = new DilithiumParameters("dilithium3shake", 3, false, false);
    public static final DilithiumParameters dilithium3R = new DilithiumParameters("dilithium3shakeR", 3, true, false);
    public static final DilithiumParameters dilithium3aes = new DilithiumParameters("dilithium3aes", 3, false, true);
    public static final DilithiumParameters dilithium3aesR = new DilithiumParameters("dilithium3aesR", 3, true, true);

    public static final DilithiumParameters dilithium5 = new DilithiumParameters("dilithium5shake", 5, false, false);
    public static final DilithiumParameters dilithium5R = new DilithiumParameters("dilithium5shakeR", 5, true, false);
    public static final DilithiumParameters dilithium5aes = new DilithiumParameters("dilithium5aes", 5, false, true);
    public static final DilithiumParameters dilithium5aesR = new DilithiumParameters("dilithium5aesR", 5, true, true);

    private final int k;
    private final String name;

    private final boolean randomizedSigning;
    private final boolean usingAES;// or shake

    private DilithiumParameters(String name, int k, boolean randomizedSigning, boolean usingAES)
    {
        this.name = name;
        this.k = k;
        this.randomizedSigning = randomizedSigning;
        this.usingAES = usingAES;

    }

    DilithiumEngine getEngine(SecureRandom random)
    {
        return new DilithiumEngine(k, random, randomizedSigning, usingAES);
    }

    public String getName()
    {
        return name;
    }
}
