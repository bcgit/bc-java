package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Parameters holder for public unified static/ephemeral agreement using Edwards Curves.
 */
public class XDHUPublicParameters
    implements CipherParameters
{
    private AsymmetricKeyParameter staticPublicKey;
    private AsymmetricKeyParameter ephemeralPublicKey;

    public XDHUPublicParameters(
        AsymmetricKeyParameter   staticPublicKey,
        AsymmetricKeyParameter   ephemeralPublicKey)
    {
        if (staticPublicKey == null)
        {
            throw new NullPointerException("staticPublicKey cannot be null");
        }
        if (!(staticPublicKey instanceof X448PublicKeyParameters || staticPublicKey instanceof X25519PublicKeyParameters))
        {
            throw new IllegalArgumentException("only X25519 and X448 paramaters can be used");
        }
        if (ephemeralPublicKey == null)
        {
            throw new NullPointerException("ephemeralPublicKey cannot be null");
        }
        if (!staticPublicKey.getClass().isAssignableFrom(ephemeralPublicKey.getClass()))
        {
            throw new IllegalArgumentException("static and ephemeral public keys have different domain parameters");
        }

        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public AsymmetricKeyParameter getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public AsymmetricKeyParameter getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
