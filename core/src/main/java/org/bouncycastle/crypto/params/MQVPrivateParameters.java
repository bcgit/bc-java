package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class MQVPrivateParameters
    implements CipherParameters
{
    private ECPrivateKeyParameters staticPrivateKey;
    private ECPrivateKeyParameters ephemeralPrivateKey;
    private ECPublicKeyParameters ephemeralPublicKey;

    public MQVPrivateParameters(
        ECPrivateKeyParameters  staticPrivateKey,
        ECPrivateKeyParameters  ephemeralPrivateKey)
    {
        this(staticPrivateKey, ephemeralPrivateKey, null);
    }

    public MQVPrivateParameters(
        ECPrivateKeyParameters  staticPrivateKey,
        ECPrivateKeyParameters  ephemeralPrivateKey,
        ECPublicKeyParameters   ephemeralPublicKey)
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

        if (ephemeralPublicKey == null)
        {
            ECPoint q = new FixedPointCombMultiplier().multiply(parameters.getG(), ephemeralPrivateKey.getD());

            ephemeralPublicKey = new ECPublicKeyParameters(q, parameters);
        }
        else if (!parameters.equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalArgumentException("Ephemeral public key has different domain parameters");
        }

        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public ECPrivateKeyParameters getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public ECPrivateKeyParameters getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public ECPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
