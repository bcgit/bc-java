package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;


public class McElieceCCA2KeyParameters
    extends AsymmetricKeyParameter
{
    private Digest params;

    public McElieceCCA2KeyParameters(
        boolean isPrivate,
        Digest params)
    {
        super(isPrivate);
        this.params = params;
    }


    public Digest getDigest()
    {
        return params;
    }

}
