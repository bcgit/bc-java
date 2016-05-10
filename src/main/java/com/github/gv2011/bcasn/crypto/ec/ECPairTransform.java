package com.github.gv2011.bcasn.crypto.ec;

import com.github.gv2011.bcasn.crypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
