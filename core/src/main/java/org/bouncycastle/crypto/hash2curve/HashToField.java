package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

/**
 * Generic implementation of hash to field
 * <p>
 * This implementation is restricted to hashing to a field where the field
 * being hashed to is derived from an Elliptic curve
 * <p>
 * The HashToField function can be used to hash to any field such as a scalar field (group order)
 * This implementation is not suitable for such cases as described in more detail in the
 * GenericOPRFHashToScalar function. Instead, this class is strictly used to implement
 * HashToField when hashing is done to curve order as this is the way the function is
 * used in HashToEllipticCurve operations.
 */
public class HashToField {

  protected final byte[] dst;
  protected final ECCurve curve;
  protected final MessageExpansion messageExpansion;
  /** Security parameter for the suite */
  protected int L;
  protected int m;
  protected BigInteger p;
  protected final int count;

  /**
   * Constructs a new instance of the HashToCurveField class.
   * <p>
   * This implementation is intended for hashing to a field derived from an elliptic curve
   * and is specifically used in the context of HashToEllipticCurve operations.
   *
   * @param dst The domain separation tag, used to separate different domains of usage to
   *            ensure distinct use cases do not produce the same output for the same input.
   * @param curve The elliptic curve from which the field to hash to is derived.
   * @param messageExpansion The mechanism for expanding input messages, ensuring the
   *                         required cryptographic properties for subsequent field hashing.
   * @param L The security parameter for the suite, determining the byte length of
   *          individual elements used in the computation.
   */
  public HashToField(final byte[] dst, final ECCurve curve,
      final MessageExpansion messageExpansion, final int L) {
    this(dst, curve, messageExpansion, L, 2);
  }

  /**
   * Constructs a new instance of the HashToCurveField class.
   * <p>
   * This constructor allows the creation of a hash-to-field mechanism tied to an elliptic curve,
   * with parameters specifying domain separation, message expansion mechanics, security level,
   * and the count of resulting field elements.
   *
   * @param dst The domain separation tag, used to separate different domains of usage to
   *            ensure distinct use cases do not produce the same output for the same input.
   * @param curve The elliptic curve from which the field to hash to is derived.
   * @param messageExpansion The mechanism for expanding input messages, ensuring the
   *                         required cryptographic properties for subsequent field hashing.
   * @param L The security parameter for the suite, determining the byte length of
   *          individual elements used in the computation.
   * @param count The number of resulting field elements to be produced during the hashing process.
   */
  public HashToField(final byte[] dst, final ECCurve curve, final MessageExpansion messageExpansion, final int L,
      final int count) {
    this.dst = dst;
    this.curve = curve;
    this.count = count;
    this.L = L;
    this.messageExpansion = messageExpansion;
    this.p = curve.getField().getCharacteristic();
    this.m = curve.getField().getDimension();
  }

  /**
   * Processes the input message and hashes it into a multidimensional array of elements
   * in a finite field derived from an elliptic curve. The hashing mechanism leverages
   * message expansion and modular arithmetic to ensure cryptographic security.
   *
   * @param message The input message to be hashed into field elements.
   * @return A two-dimensional array of BigInteger, where each entry represents a field
   *         element derived from the input message.
   */
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
