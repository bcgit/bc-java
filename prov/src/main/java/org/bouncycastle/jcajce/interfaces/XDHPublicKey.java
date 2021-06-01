package org.bouncycastle.jcajce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

public interface XDHPublicKey
    extends XDHKey, PublicKey
{
    public BigInteger getU();

    public byte[] getUEncoding();
}
