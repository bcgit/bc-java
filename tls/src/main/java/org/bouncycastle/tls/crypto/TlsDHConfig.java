package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

public interface TlsDHConfig
{
    BigInteger[] getExplicitPG();
}
