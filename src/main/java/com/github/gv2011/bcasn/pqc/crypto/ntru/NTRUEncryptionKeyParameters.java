package com.github.gv2011.bcasn.pqc.crypto.ntru;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public class NTRUEncryptionKeyParameters
    extends AsymmetricKeyParameter
{
    final protected NTRUEncryptionParameters params;

    public NTRUEncryptionKeyParameters(boolean privateKey, NTRUEncryptionParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public NTRUEncryptionParameters getParameters()
    {
        return params;
    }
}
