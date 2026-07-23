/**
 * Curve, extension-field and pairing arithmetic for the SM9 identity-based
 * cryptographic algorithms (GM/T 0044.5-2016): the 256-bit Barreto-Naehrig curve
 * with its G1 group (see {@link org.bouncycastle.math.ec.sm9.SM9Curve}, backed by
 * the constant-time Montgomery curve
 * {@link org.bouncycastle.math.ec.custom.gm.SM9P256V1Curve}), the G2 sextic twist over F_p2
 * ({@link org.bouncycastle.math.ec.sm9.SM9G2Point}), the F_p2/F_p4/F_p12
 * 1-2-4-12 tower, and the R-ate pairing e: G1 x G2 -&gt; G_T
 * ({@link org.bouncycastle.math.ec.sm9.SM9Pairing}, target group
 * {@link org.bouncycastle.math.ec.sm9.Fp12}). The SM9 schemes built on this
 * package live in the standard lightweight packages: the signer in
 * {@code org.bouncycastle.crypto.signers}, the KEM in {@code org.bouncycastle.crypto.kems},
 * the public-key cipher in {@code org.bouncycastle.crypto.engines}, the key exchange in
 * {@code org.bouncycastle.crypto.agreement}, the master key-pair generators in
 * {@code org.bouncycastle.crypto.generators} and the key parameters in
 * {@code org.bouncycastle.crypto.params}.
 */
package org.bouncycastle.math.ec.sm9;
