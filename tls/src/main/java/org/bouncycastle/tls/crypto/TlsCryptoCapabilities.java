package org.bouncycastle.tls.crypto;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.util.Integers;

/**
 * Holder for capabilities, such as EC supported curves that we would like to see in a TlsCrypto.
 */
public class TlsCryptoCapabilities
{
    private final Set<Integer> supportedNamedCurves;

    /**
     * Base constructor.
     *
     * @param supportedNamedCurves an array of supported curve ids.
     */
    public TlsCryptoCapabilities(int[] supportedNamedCurves)
    {
        Set curves = new HashSet(supportedNamedCurves.length);
        for (int i = 0; i != supportedNamedCurves.length; i++)
        {
            curves.add(Integers.valueOf(supportedNamedCurves[i]));
        }

        this.supportedNamedCurves = Collections.unmodifiableSet(curves);
    }

    /**
     * Return the named curves we support, or want supported.
     *
     * @return a Set of supported named curves.
     */
    public Set<Integer> getSupportedNamedCurves()
    {
        return supportedNamedCurves;
    }
}
