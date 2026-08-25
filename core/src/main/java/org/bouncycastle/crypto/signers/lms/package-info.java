/**
 * Engine for LMS and the HSS multi-tree variant per RFC 8554 (hash-based stateful signatures).
 * The public classes here are {@link org.bouncycastle.crypto.signers.lms.LMSEngine}, the
 * operations the key parameter classes in {@link org.bouncycastle.crypto.params} and the key pair
 * generators in {@link org.bouncycastle.crypto.generators} are built on,
 * {@link org.bouncycastle.crypto.signers.lms.LMSContext}, the digest a message is absorbed into
 * before it is signed or verified, and {@link org.bouncycastle.crypto.signers.lms.LMSSignature},
 * the opaque form of an LMS signature an HSS private key carries its chaining signatures in.
 * Everything else is package-private. Applications sign and verify through
 * {@link org.bouncycastle.crypto.signers.LMSSigner} / {@link org.bouncycastle.crypto.signers.HSSSigner}.
 */
package org.bouncycastle.crypto.signers.lms;
