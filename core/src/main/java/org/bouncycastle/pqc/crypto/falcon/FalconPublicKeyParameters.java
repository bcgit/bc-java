package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

public class FalconPublicKeyParameters
    extends FalconKeyParameters
{
    private final byte[] H;

    public FalconPublicKeyParameters(FalconParameters parameters, byte[] H)
    {
        super(false, parameters);
        // H carries the modq-encoded public polynomial (the leading header byte
        // is stripped by the decoder), so its length is fixed per degree.
        if (H.length != 14 * (1 << parameters.getLogN()) / 8)
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
