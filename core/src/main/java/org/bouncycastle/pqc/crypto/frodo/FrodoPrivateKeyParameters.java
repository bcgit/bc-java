package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.util.Arrays;

/**
 * @deprecated the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see FrodoKEMParameters / FrodoKEMParameterSpec). This is the legacy NIST round 3 (unsalted, eFrodoKEM) implementation, retained for backwards compatibility.
 */
@Deprecated
public class FrodoPrivateKeyParameters
    extends FrodoKeyParameters
{
    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public FrodoPrivateKeyParameters(FrodoParameters params, byte[] privateKey)
    {
        super(true, params);

        if (privateKey.length != params.getEngine().getPrivateKeySize())
        {
            throw new IllegalArgumentException("'privateKey' has invalid length");
        }

        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }
}
