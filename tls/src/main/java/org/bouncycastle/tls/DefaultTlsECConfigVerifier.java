package org.bouncycastle.tls;

import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.util.Integers;

public class DefaultTlsECConfigVerifier
    implements TlsECConfigVerifier
{
    protected int minimumCurveBits;
    protected Vector namedGroups; 

    public DefaultTlsECConfigVerifier(int minimumCurveBits, Vector namedGroups)
    {
        this.minimumCurveBits = Math.max(1, minimumCurveBits);
        this.namedGroups = namedGroups;
    }

    public boolean accept(TlsECConfig ecConfig)
    {
        int namedGroup = ecConfig.getNamedGroup();

        if (ecConfig.getPointCompression())
        {
            switch (namedGroup)
            {
            case NamedGroup.x25519:
            case NamedGroup.x448:
                return false;
            default:
                // NOTE: Any value of ecConfig.pointCompression is acceptable
                break;
            }
        }

        if (namedGroup < 0)
        {
            return false;
        }

        if (NamedGroup.getCurveBits(namedGroup) < minimumCurveBits)
        {
            return false;
        }

        if (namedGroups != null && !namedGroups.contains(Integers.valueOf(namedGroup)))
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
