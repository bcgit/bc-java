package com.github.gv2011.bcasn.crypto.ec;

import com.github.gv2011.bcasn.crypto.CipherParameters;
import com.github.gv2011.bcasn.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
