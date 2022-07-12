package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPublicKeyParameters
    extends FalconKeyParameters
{

    private byte[] pk;

    public FalconPublicKeyParameters(FalconParameters parameters, byte[] pk_encoded)
    {
        super(false, parameters);
        this.pk = Arrays.clone(pk_encoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(pk);
    }
}
