package com.github.gv2011.bcasn.crypto;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}
