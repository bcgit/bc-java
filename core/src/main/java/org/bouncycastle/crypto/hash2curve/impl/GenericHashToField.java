package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.HashToField;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

/**
 * Generic implementation of hash to field
 */
public class GenericHashToField implements HashToField {

  protected final byte[] dst;
  protected final ECCurve curve;
  protected final MessageExpansion messageExpansion;
  /** Security parameter for the suite */
  protected int L;
  protected int m;
  protected BigInteger p;
  protected final int count;

  public GenericHashToField(final byte[] dst, final ECCurve curve,
      final MessageExpansion messageExpansion, final int L) {
    this(dst, curve, messageExpansion, L, 2);
  }

  public GenericHashToField(final byte[] dst, final ECCurve curve, final MessageExpansion messageExpansion, final int L,
      final int count) {
    this.dst = dst;
    this.curve = curve;
    this.count = count;
    this.L = L;
    this.messageExpansion = messageExpansion;
    this.p = curve.getField().getCharacteristic();
    this.m = curve.getField().getDimension();
  }

  @Override
  public BigInteger[][] process(final byte[] message) {

    final int byteLen = this.count * this.m * this.L;
    final byte[] uniformBytes = this.messageExpansion.expandMessage(message, this.dst, byteLen);
    final BigInteger[][] u = new BigInteger[this.count][this.m];
    for (int i = 0; i < this.count; i++) {
      final BigInteger[] e = new BigInteger[this.m];
      for (int j = 0; j < this.m; j++) {
        final int elmOffset = this.L * (j + i * this.m);
        final byte[] tv = Arrays.copyOfRange(uniformBytes, elmOffset, elmOffset + this.L);
        e[j] = H2cUtils.os2ip(tv).mod(this.p);
      }
      u[i] = e;
    }
    return u;
  }
}
