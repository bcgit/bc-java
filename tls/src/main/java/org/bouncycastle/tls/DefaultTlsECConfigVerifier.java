package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Arrays;

public class DefaultTlsECConfigVerifier
    implements TlsECConfigVerifier
{
    protected int minimumCurveBits;
    protected int[] namedCurves;

    public DefaultTlsECConfigVerifier(int minimumCurveBits, int[] namedCurves)
    {
        this.minimumCurveBits = minimumCurveBits;
        this.namedCurves = Arrays.clone(namedCurves);
    }

    public boolean accept(TlsECConfig ecConfig)
    {
        // NOTE: Any value of ecConfig.pointCompression is acceptable

        int namedCurve = ecConfig.getNamedCurve();

        if (NamedCurve.getCurveBits(namedCurve) < minimumCurveBits)
        {
            return false;
        }

        if (namedCurves != null && !Arrays.contains(namedCurves, namedCurve))
        {
            /*
             * RFC 4492 4. [...] servers MUST NOT negotiate the use of an ECC cipher suite unless
             * they can complete the handshake while respecting the choice of curves and compression
             * techniques specified by the client.
             */
            return false;
        }

        return true;
    }
}
