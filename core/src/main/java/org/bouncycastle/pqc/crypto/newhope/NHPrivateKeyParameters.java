package org.bouncycastle.pqc.crypto.newhope;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public class NHPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    final short[] secData;

    public NHPrivateKeyParameters(short[] secData)
    {
        super(true);

        this.secData = Arrays.clone(secData);
    }

    public short[] getSecData()
    {
        return Arrays.clone(secData);
    }
}
