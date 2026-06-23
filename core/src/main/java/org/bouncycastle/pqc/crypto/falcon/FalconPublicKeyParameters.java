package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPublicKeyParameters
    extends FalconKeyParameters
{
    private final byte[] H;

    public FalconPublicKeyParameters(FalconParameters parameters, byte[] H)
    {
        super(false, parameters);
        int n = 1 << parameters.getLogN();
        if (H.length != (14 * n / 8))
        {
            throw new IllegalArgumentException("'H' has invalid length");
        }
        this.H = Arrays.clone(H);
    }

    public byte[] getH()
    {
        return Arrays.clone(H);
    }
}
