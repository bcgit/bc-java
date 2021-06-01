package org.bouncycastle.jcajce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

public interface XDHPublicKey
    extends XDHKey, PublicKey
{
    BigInteger getU();

    byte[] getUEncoding();
}
