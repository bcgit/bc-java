package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.util.Arrays;

public class DilithiumPublicKeyParameters
    extends DilithiumKeyParameters
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

    public DilithiumPublicKeyParameters(DilithiumParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
