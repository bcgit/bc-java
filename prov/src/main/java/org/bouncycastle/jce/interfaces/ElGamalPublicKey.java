package org.bouncycastle.jce.interfaces;

import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;

/**
 * @deprecated just use DHPublicKey.
 */
public interface ElGamalPublicKey
    extends ElGamalKey, DHPublicKey
{
    public BigInteger getY();
}
