package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.NamedCurve;

/**
 * Default value object for supported capabilities.
 */
public class DefaultTlsCryptoCapabilities
    extends TlsCryptoCapabilities
{
    private static final int[] namedCurves = new int[]{ NamedCurve.secp256r1, NamedCurve.secp384r1 };

    public DefaultTlsCryptoCapabilities()
    {
        super(namedCurves);
    }
}
