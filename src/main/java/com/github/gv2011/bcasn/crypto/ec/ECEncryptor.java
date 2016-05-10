package com.github.gv2011.bcasn.crypto.ec;

import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
