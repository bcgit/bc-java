package org.bouncycastle.crypto.constraints;

import java.util.Set;

class Utils
{
    /**
     * Depending on usage, in some places algorithms are referred to slightly
     * differently. We try to sort that out here.
     *
     * @param exceptions set of exceptions from constraint checking.
     */
    static void addAliases(Set<String> exceptions)
    {
        if (exceptions.contains("RC4"))
        {
            exceptions.add("ARC4");
        }
        else if (exceptions.contains("ARC4"))
        {
            exceptions.add("RC4");
        }
    }
}
