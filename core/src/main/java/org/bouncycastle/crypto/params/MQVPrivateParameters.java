package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

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
        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.ephemeralPublicKey = (ephemeralPublicKey != null) ?
            ephemeralPublicKey : new ECPublicKeyParameters(ephemeralPrivateKey.getParameters().getG().multiply(ephemeralPrivateKey.getD()), ephemeralPrivateKey.getParameters());

        if (!staticPrivateKey.getParameters().equals(ephemeralPrivateKey.getParameters())
            || !staticPrivateKey.getParameters().equals(this.ephemeralPublicKey.getParameters()))
        {
            throw new IllegalArgumentException("Static and ephemeral keys have different domain parameters");
        }
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
