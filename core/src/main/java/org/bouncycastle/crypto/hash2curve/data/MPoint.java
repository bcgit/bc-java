package org.bouncycastle.crypto.hash2curve.data;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class MPoint {

  final BigInteger x;
  final BigInteger y;

  public MPoint(final BigInteger x, final BigInteger y) {
    this.x = x;
    this.y = y;
  }

  public BigInteger getX() {
    return x;
  }

  public BigInteger getY() {
    return y;
  }
}
