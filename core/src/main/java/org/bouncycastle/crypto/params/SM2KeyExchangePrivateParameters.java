package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

/**
 * Private parameters for an SM2 key exchange. The ephemeralPrivateKey is used to calculate the random point used in the algorithm.
 */
public class SM2KeyExchangePrivateParameters
    implements CipherParameters
{
    private final boolean initiator;
    private final ECPrivateKeyParameters staticPrivateKey;
    private final ECPoint staticPublicPoint;
    private final ECPrivateKeyParameters ephemeralPrivateKey;
    private final ECPoint ephemeralPublicPoint;

    public SM2KeyExchangePrivateParameters(
        boolean initiator,
        ECPrivateKeyParameters staticPrivateKey,
        ECPrivateKeyParameters ephemeralPrivateKey)
    {
        if (staticPrivateKey == null)
        {
            throw new NullPointerException("staticPrivateKey cannot be null");
        }
        if (ephemeralPrivateKey == null)
        {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        }

        ECDomainParameters parameters = staticPrivateKey.getParameters();
        if (!parameters.equals(ephemeralPrivateKey.getParameters()))
        {
            throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters");
        }

        ECMultiplier m = new FixedPointCombMultiplier();

        this.initiator = initiator;
        this.staticPrivateKey = staticPrivateKey;
        this.staticPublicPoint = m.multiply(parameters.getG(), staticPrivateKey.getD()).normalize();
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.ephemeralPublicPoint = m.multiply(parameters.getG(), ephemeralPrivateKey.getD()).normalize();
    }

    public boolean isInitiator()
    {
        return initiator;
    }
    public ECPrivateKeyParameters getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public ECPoint getStaticPublicPoint()
    {
        return staticPublicPoint;
    }

    public ECPrivateKeyParameters getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public ECPoint getEphemeralPublicPoint()
    {
        return ephemeralPublicPoint;
    }
}
