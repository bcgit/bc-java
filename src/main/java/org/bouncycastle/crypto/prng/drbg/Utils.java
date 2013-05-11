package org.bouncycastle.crypto.prng.drbg;

import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.util.Integers;

class Utils
{
    static final Hashtable maxSecurityStrengths = new Hashtable();

    static
    {
        maxSecurityStrengths.put("SHA-1", Integers.valueOf(128));

        maxSecurityStrengths.put("SHA-224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-256", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-384", Integers.valueOf(256));
        maxSecurityStrengths.put("SHA-512", Integers.valueOf(256));

        maxSecurityStrengths.put("SHA-512/224", Integers.valueOf(192));
        maxSecurityStrengths.put("SHA-512/256", Integers.valueOf(256));
    }

    static int getMaxSecurityStrength(Digest d)
    {
        return ((Integer)maxSecurityStrengths.get(d.getAlgorithmName())).intValue();
    }

    static int getMaxSecurityStrength(Mac m)
    {
        String name = m.getAlgorithmName();

        return ((Integer)maxSecurityStrengths.get(name.substring(0, name.indexOf("/")))).intValue();
    }
}
