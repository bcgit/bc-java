package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;

/**
 * @deprecated the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see org.bouncycastle.crypto.params.CMCEParameters and org.bouncycastle.jcajce.spec.CMCEParameterSpec). This is the legacy NIST round 3 (non-pc, incl. mceliece348864) implementation, retained for backwards compatibility.
 */
@Deprecated
public class CMCEPublicKeyParameters
    extends CMCEKeyParameters
{
    private final byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public CMCEPublicKeyParameters(CMCEParameters params, byte[] publicKey)
    {
        super(false, params);

        if (publicKey.length != params.getEngine().getPublicKeySize())
        {
            throw new IllegalArgumentException("'publicKey' has invalid length");
        }

        this.publicKey = Arrays.clone(publicKey);
    }
}
