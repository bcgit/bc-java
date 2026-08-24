/**
 * Internal engine classes for LMS and the HSS multi-tree variant per RFC 8554 (hash-based
 * stateful signatures). The public surface of the scheme is the key parameter classes in
 * {@link org.bouncycastle.crypto.params}, the key pair generators in
 * {@link org.bouncycastle.crypto.generators}, and
 * {@link org.bouncycastle.crypto.signers.LMSSigner} / {@link org.bouncycastle.crypto.signers.HSSSigner}.
 */
package org.bouncycastle.crypto.signers.lms;
