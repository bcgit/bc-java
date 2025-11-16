package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.hash2curve.HashToScalar;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;

/**
 * Generic implementation of Hash to Scalar for OPRF
 */
public class GenericOPRFHashToScalar implements HashToScalar {

  private final ECCurve curve;
  private final MessageExpansion messageExpansion;

  private final int L;

  public GenericOPRFHashToScalar(final ECCurve curve, final Digest digest, final int k) {
    this.curve = curve;
    this.L =
        (int) Math.ceil(((double) curve.getOrder().subtract(BigInteger.ONE).bitLength() + k) / 8);
    this.messageExpansion = new XmdMessageExpansion(digest, k);
  }

  @Override
  public BigInteger process(final byte[] input, final byte[] dst) {
    final byte[] expandMessage = this.messageExpansion.expandMessage(input, dst, this.L);
    return new BigInteger(1, expandMessage).mod(this.curve.getOrder());
  }
}
