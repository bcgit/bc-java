/**
 * BLS signatures over the BLS12-381 curve, per draft-irtf-cfrg-bls-signature.
 * <p>
 * The three ciphersuite variants are provided as static-API classes —
 * {@link org.bouncycastle.crypto.bls.BLS12_381BasicScheme},
 * {@link org.bouncycastle.crypto.bls.BLS12_381MessageAugmentation} and
 * {@link org.bouncycastle.crypto.bls.BLS12_381ProofOfPossession} — with a BC-conventional
 * signer / key-pair generator surface alongside in {@code org.bouncycastle.crypto.signers}
 * ({@code BLSSigner}) and {@code org.bouncycastle.crypto.generators} ({@code BLSKeyPairGenerator}).
 * Keys and signatures use the compressed Zcash point encoding (48-byte G1 public keys,
 * 96-byte G2 signatures).
 */
package org.bouncycastle.crypto.bls;
