package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Parameters holder for public unified static/ephemeral agreement as described in NIST SP 800-56A using EC DH/CDH.
 */
public class ECDHEPublicParameters
    implements CipherParameters
{
    private ECPublicKeyParameters staticPublicKey;
    private ECPublicKeyParameters ephemeralPublicKey;

    public ECDHEPublicParameters(
        ECPublicKeyParameters   staticPublicKey,
        ECPublicKeyParameters   ephemeralPublicKey)
    {
        if (staticPublicKey == null)
        {
            throw new NullPointerException("staticPublicKey cannot be null");
        }
        if (ephemeralPublicKey == null)
        {
            throw new NullPointerException("ephemeralPublicKey cannot be null");
        }
        if (!staticPublicKey.getParameters().equals(ephemeralPublicKey.getParameters()))
        {
            throw new IllegalArgumentException("static and ephemeral public keys have different domain parameters");
        }

        this.staticPublicKey = staticPublicKey;
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public ECPublicKeyParameters getStaticPublicKey()
    {
        return staticPublicKey;
    }

    public ECPublicKeyParameters getEphemeralPublicKey()
    {
        return ephemeralPublicKey;
    }
}
