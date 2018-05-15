package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Parameters holder for private unified static/ephemeral agreement as described in NIST SP 800-56A.
 */
public class DHUPrivateParameters
    implements CipherParameters
{
    private DHPrivateKeyParameters staticPrivateKey;
    private DHPrivateKeyParameters ephemeralPrivateKey;
    private DHPublicKeyParameters ephemeralPublicKey;

    public DHUPrivateParameters(
        DHPrivateKeyParameters  staticPrivateKey,
        DHPrivateKeyParameters  ephemeralPrivateKey)
    {
        this(staticPrivateKey, ephemeralPrivateKey, null);
    }

    public DHUPrivateParameters(
        DHPrivateKeyParameters  staticPrivateKey,
        DHPrivateKeyParameters  ephemeralPrivateKey,
        DHPublicKeyParameters   ephemeralPublicKey)
    {
        if (staticPrivateKey == null)
        {
            throw new NullPointerException("staticPrivateKey cannot be null");
        }
        if (ephemeralPrivateKey == null)
        {
            throw new NullPointerException("ephemeralPrivateKey cannot be null");
        }

        DHParameters parameters = staticPrivateKey.getParameters();
        if (!parameters.equals(ephemeralPrivateKey.getParameters()))
        {
            throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
        }

        if (ephemeralPublicKey == null)
        {
            ephemeralPublicKey = new DHPublicKeyParameters(
                parameters.getG().modPow(ephemeralPrivateKey.getX(), parameters.getP()),
                parameters);
        }
        else if (!parameters.equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalArgumentException("ephemeral public key has different domain parameters");
        }

        this.staticPrivateKey = staticPrivateKey;
        this.ephemeralPrivateKey = ephemeralPrivateKey;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public DHPrivateKeyParameters getStaticPrivateKey()
    {
        return staticPrivateKey;
    }

    public DHPrivateKeyParameters getEphemeralPrivateKey()
    {
        return ephemeralPrivateKey;
    }

    public DHPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
