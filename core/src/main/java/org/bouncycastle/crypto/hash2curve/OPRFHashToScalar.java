package org.bouncycastle.crypto.hash2curve;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;

/**
 * Generic implementation of HashToScalar as used in OPRF (RFC 9497).
 *
 * <p>This implementation intentionally provides a *single* unified HashToScalar construction for
 * all supported prime-order elliptic curve groups (P-256, P-384, P-521, Curve25519, Ristretto255,
 * and Decaf448). Although RFC 9497 appears to specify different procedures for NIST curves and
 * Edwards-family curves, these procedures are mathematically equivalent to one another and can be
 * implemented using one common algorithm.</p>
 *
 * <h2>Background</h2>
 *
 * <p>RFC 9497 defines HashToScalar as follows:</p>
 * <ul>
 *   <li>For NIST curves: use {@code hash_to_field} from RFC 9380 with modulus equal to the group
 *       order.</li>
 *   <li>For other curves (Curve25519, Ristretto255, Decaf448): expand the input using
 *       {@code expand_message_xmd}, interpret the output as an integer, and reduce it modulo the
 *       group order.</li>
 * </ul>
 *
 * <p>At first glance these appear to be fundamentally different algorithms. However, RFC 9380
 * explicitly defines {@code hash_to_field} as a generic mechanism for producing field elements
 * modulo an arbitrary prime, not only the curve base field. When {@code hash_to_field} is invoked
 * with:</p>
 *
 * <pre>
 *   m     = 1
 *   count = 1
 *   p     = group order q     (not the curve field prime)
 * </pre>
 *
 * <p>the definition collapses to the simpler:</p>
 *
 * <pre>
 *   uniform_bytes = expand_message_xmd(msg, DST, L)
 *   scalar        = OS2IP(uniform_bytes) mod q
 * </pre>
 *
 * <p>where {@code L = ceil((log2(q) + k) / 8)} and {@code k} is the security parameter for the
 * ciphersuite. This is precisely the construction used for the Edwards-family curves. In other
 * words, *both branches of RFC 9497 ultimately specify the same mathematical operation*.</p>
 *
 * <h2>Rationale for a unified implementation</h2>
 *
 * <p>Using a single generic implementation has several advantages:</p>
 * <ul>
 *   <li>It avoids duplicating two code paths that differ only superficially.</li>
 *   <li>It eliminates any ambiguity between curve field primes and group-order primes.</li>
 *   <li>It aligns with how real-world OPRF implementations are written (e.g., CIRCL/Go,
 *       Cloudflare VOPRF, Rust <code>voprf</code>, HACL*, etc.), which all use the
 *       "expand → integer → mod q" construction directly.</li>
 *   <li>It provides a consistent and auditable design across all curves.</li>
 * </ul>
 *
 * <p>For these reasons, this class implements the general form:</p>
 *
 * <pre>
 *   uniform_bytes = expand_message_xmd(msg, DST, L)
 *   scalar        = OS2IP(uniform_bytes) mod group_order
 * </pre>
 *
 * <p>This behavior is fully compliant with RFC 9497 and RFC 9380 and is applicable to all
 * prime-order elliptic-curve groups.</p>
 */
public class OPRFHashToScalar {

  private final ECCurve curve;
  private final MessageExpansion messageExpansion;

  private final int L;

  public OPRFHashToScalar(final ECCurve curve, final Digest digest, final int k) {
    this.curve = curve;
    this.L =
        (int) Math.ceil(((double) curve.getOrder().subtract(BigInteger.ONE).bitLength() + k) / 8);
    this.messageExpansion = new XmdMessageExpansion(digest, k);
  }

  public BigInteger process(final byte[] input, final byte[] dst) {
    final byte[] expandMessage = this.messageExpansion.expandMessage(input, dst, this.L);
    return new BigInteger(1, expandMessage).mod(this.curve.getOrder());
  }
}
