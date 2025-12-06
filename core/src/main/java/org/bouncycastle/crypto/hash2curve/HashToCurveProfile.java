package org.bouncycastle.crypto.hash2curve;

import java.math.BigInteger;

/**
 * Supported profiles for hash to curve
 * <p>
 * _NU_ is identical to _RO_, *    except that the encoding type is encode_to_curve. encode_to_curve is not yet
 * implemented in this lib, thus these options are not yet included
 */
public enum HashToCurveProfile {

  P256_XMD_SHA_256_SSWU_RO_("P256_XMD:SHA-256_SSWU_RO_", BigInteger.valueOf(-10), 48, 128, 1, null, null),
  //  P256_XMD_SHA_256_SSWU_NU_("P256_XMD:SHA-256_SSWU_NU_", BigInteger.valueOf(-10), 128),
  P384_XMD_SHA_384_SSWU_RO_("P384_XMD:SHA-384_SSWU_RO_", BigInteger.valueOf(-12), 72, 192, 1, null, null),
  //  P384_XMD_SHA_384_SSWU_NU_("P384_XMD:SHA-384_SSWU_NU_", BigInteger.valueOf(-12), 192),
  P521_XMD_SHA_512_SSWU_RO_("P521_XMD:SHA-512_SSWU_RO_", BigInteger.valueOf(-4), 98, 256, 1, null, null),
  //  P521_XMD_SHA_512_SSWU_NU_("P521_XMD:SHA-512_SSWU_NU_", BigInteger.valueOf(-4), 256),
  curve25519_XMD_SHA_512_ELL2_RO_("curve25519_XMD:SHA-512_ELL2_RO_", BigInteger.valueOf(2), 48, 128, 8, 486662, 1),
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
  /** Block length */
  private final int L;
  /** The target security level in bits for the curve */
  private final int k;
  /** Effective cofactor */
  private final int h;
  /** Montgomery A parameter */
  private final Integer mJ;
  /** Montgomery B parameter */
  private final Integer mK;

  HashToCurveProfile(final String cipherSuiteID, final BigInteger z, final int l, final int k, int h, Integer mJ, Integer mK) {
    this.cipherSuiteID = cipherSuiteID;
    this.Z = z;
    this.L = l;
    this.k = k;
    this.h = h;
    this.mJ = mJ;
    this.mK = mK;
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

  public int getH() {
    return h;
  }

  public Integer getmJ() {
    return mJ;
  }

  public Integer getmK() {
    return mK;
  }
}
