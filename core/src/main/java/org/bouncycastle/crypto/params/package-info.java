/**
 * Classes for parameter objects for ciphers and generators.
 * <p>
 * Several parameter types in this package are <b>wrappers</b>: each carries one extra value and a
 * {@code getParameters()} link to the {@link org.bouncycastle.crypto.CipherParameters} it decorates,
 * so a caller supplies a nested chain ending in a key. The wrappers are
 * {@link org.bouncycastle.crypto.params.ParametersWithContext},
 * {@link org.bouncycastle.crypto.params.ParametersWithID},
 * {@link org.bouncycastle.crypto.params.ParametersWithRandom},
 * {@link org.bouncycastle.crypto.params.ParametersWithUKM},
 * {@link org.bouncycastle.crypto.params.ParametersWithIV},
 * {@link org.bouncycastle.crypto.params.ParametersWithSBox} and
 * {@link org.bouncycastle.crypto.params.ParametersWithSalt}.
 * <p>
 * There is no enforced nesting order, but the implementations share a de facto one. A component
 * unwraps only the wrapper it consumes and passes the remainder down, so a wrapper sits
 * <em>outside</em> everything consumed further down the stack. Outermost first, the order used
 * throughout the lightweight API and by the JCE provider when it builds these chains is:
 * <ul>
 * <li>{@code ParametersWithContext}, {@code ParametersWithID} or {@code ParametersWithUKM} - a
 * signature context string (ML-DSA, SLH-DSA and similar), a signer identity (SM2, SM9), or the
 * user keying material of the GOST 28147 wrap engines and the VKO key agreement, consumed by the
 * signer, wrap engine or agreement.</li>
 * <li>{@code ParametersWithRandom} - consumed by the outermost component that needs randomness:
 * a signer, an asymmetric encoding, a wrap engine, or a padded buffered cipher. Block cipher
 * modes and stream ciphers do not unwrap it, so it must not be nested inside an IV.</li>
 * <li>{@code ParametersWithIV} - the IV or nonce, consumed by the cipher mode, stream cipher or
 * MAC.</li>
 * <li>{@code ParametersWithSBox} - the GOST 28147 S-box, consumed by the engine and so placed
 * directly around the key.</li>
 * <li>the key itself: {@link org.bouncycastle.crypto.params.KeyParameter} or an
 * {@link org.bouncycastle.crypto.params.AsymmetricKeyParameter}.</li>
 * </ul>
 * So, for example, a GOST 28147 CBC cipher takes {@code IV(SBox(key))}, a padded CBC cipher takes
 * {@code Random(IV(key))}, an ML-DSA signer takes {@code Context(Random(privateKey))}, and a
 * GOST 28147 wrap engine takes {@code UKM(Random(SBox(key)))}. The GOST 28147 wrap engines also
 * still accept the earlier {@code Random(UKM(SBox(key)))}.
 * <p>
 * {@code ParametersWithSalt} is used only by
 * {@link org.bouncycastle.crypto.signers.ISO9796d2PSSSigner}, which accepts it as an alternative
 * to {@code ParametersWithRandom} rather than nested with it. A few GOST classes
 * ({@link org.bouncycastle.crypto.macs.GOST28147Mac} in particular) accept their wrappers in any
 * order; most implementations do not, and a chain nested against the order above is usually
 * rejected with an {@code IllegalArgumentException} or a {@code ClassCastException}.
 * {@link org.bouncycastle.crypto.params.AEADParameters} is a self-contained alternative to
 * {@code ParametersWithIV} for AEAD modes and combines key, nonce, tag length and associated data
 * without nesting.
 * <p>
 * Rejecting other nestings is intended. New code should accept the order above and nothing else.
 * Accepting an alternative order is a compatibility measure, and is justified only where existing
 * callers are known to build it, as with the earlier {@code Random(UKM(..))} of the GOST 28147 wrap
 * engines. An alternative added speculatively becomes a second form that every caller, wrapper and
 * port then has to keep supporting.
 */
package org.bouncycastle.crypto.params;
