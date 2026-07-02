package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.util.Arrays;

/**
 * @deprecated the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see FrodoKEMParameters / FrodoKEMParameterSpec). This is the legacy NIST round 3 (unsalted, eFrodoKEM) implementation, retained for backwards compatibility.
 */
@Deprecated
public class FrodoPublicKeyParameters
    extends FrodoKeyParameters
{

    public byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public FrodoPublicKeyParameters(FrodoParameters params, byte[] publicKey)
    {
        super(false, params);

        if (publicKey.length != params.getEngine().getPublicKeySize())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }

        this.publicKey = Arrays.clone(publicKey);
    }
}
