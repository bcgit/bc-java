package org.bouncycastle.crypto.hash2curve;

import java.math.BigInteger;

/**
 * Supported profiles for hash to curve
 * <p>
 * _NU_ is identical to _RO_, *    except that the encoding type is encode_to_curve. encode_to_curve is not yet
 * implemented in this lib, thus these options are not yet included
 */
public enum HashToCurveProfile {

  P256_XMD_SHA_256_SSWU_RO_("P256_XMD:SHA-256_SSWU_RO_", BigInteger.valueOf(-10), 48, 128),
  //  P256_XMD_SHA_256_SSWU_NU_("P256_XMD:SHA-256_SSWU_NU_", BigInteger.valueOf(-10), 128),
  P384_XMD_SHA_384_SSWU_RO_("P384_XMD:SHA-384_SSWU_RO_", BigInteger.valueOf(-12), 72, 192),
  //  P384_XMD_SHA_384_SSWU_NU_("P384_XMD:SHA-384_SSWU_NU_", BigInteger.valueOf(-12), 192),
  P521_XMD_SHA_512_SSWU_RO_("P521_XMD:SHA-512_SSWU_RO_", BigInteger.valueOf(-4), 98, 256),
  //  P521_XMD_SHA_512_SSWU_NU_("P521_XMD:SHA-512_SSWU_NU_", BigInteger.valueOf(-4), 256),
  curve25519_XMD_SHA_512_ELL2_RO_("curve25519_XMD:SHA-512_ELL2_RO_", BigInteger.valueOf(2), 48, 128),
  //  curve25519_XMD_SHA_512_ELL2_NU_("curve25519_XMD:SHA-512_ELL2_NU_", BigInteger.valueOf(2), 128),
  ;

  /** The cipher suite ID */
  private final String cipherSuiteID;

  /**
   * The z value is a value of the curve field that satisfies the following criteria:
   * <ol>
   *   <li>Z is non-square in F. This is a field object e.g., F = GF(2^521 - 1).</li>
   *   <li>Z is not equal to negative one -1 in the field F.</li>
   *   <li>The polynomial g(x) - Z is irreducible over the field F. In this context, an irreducible polynomial cannot be factored into polynomials of lower degree, also in the field F</li>
   *   <li>The polynomial g(B / (Z * A)) should be a square number in the field F</li>
   * </ol>
   */
  private final BigInteger Z;
  /** The target security level in bits for the curve */
  private final int L;
  private final int k;

  HashToCurveProfile(final String cipherSuiteID, final BigInteger z, final int l, final int k) {
    this.cipherSuiteID = cipherSuiteID;
    Z = z;
    L = l;
    this.k = k;
  }

  public String getCipherSuiteID() {
    return cipherSuiteID;
  }

  public int getK() {
    return k;
  }

  public int getL() {
    return L;
  }

  public BigInteger getZ() {
    return Z;
  }
}
