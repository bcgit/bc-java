package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPublicKeyParameters
    extends FalconKeyParameters
{
    private byte[] H;

    public FalconPublicKeyParameters(FalconParameters parameters, byte[] H)
    {
        super(false, parameters);
        this.H = Arrays.clone(H);
    }

    public byte[] getH()
    {
        return Arrays.clone(H);
    }
}
