package org.bouncycastle.operator;

/**
 * Base checked exception for failures originating in the {@code org.bouncycastle.operator}
 * abstraction layer &mdash; the bridge between BC's JCA-free high-level packages
 * ({@code org.bouncycastle.cms}, {@code org.bouncycastle.cert}, {@code org.bouncycastle.pkcs},
 * etc.) and their underlying JCA / lightweight implementations
 * ({@code org.bouncycastle.operator.jcajce} / {@code org.bouncycastle.operator.bc}).
 * <p>
 * Operators are the small, focused capability interfaces in this package &mdash;
 * {@code ContentSigner}, {@code ContentVerifier}, {@code DigestCalculator},
 * {@code MacCalculator}, {@code KeyWrapper}, {@code OutputEncryptor}, and so on &mdash;
 * that callers obtain from concrete builders. {@code OperatorException} (and its
 * subclasses) are the way those builders and the operators themselves report failure
 * back to the high-level code, without that high-level code having to declare
 * {@code java.security.*} / {@code javax.crypto.*} checked exceptions in its API.
 * <p>
 * Direct subclasses:
 * <ul>
 *   <li>{@link OperatorCreationException} &mdash; thrown by an operator <em>builder</em>
 *       (e.g. {@code JcaContentSignerBuilder}, {@code BcRSAContentSignerBuilder},
 *       {@code JcaDigestCalculatorProviderBuilder}) when it cannot produce the
 *       requested operator. Typical underlying causes include an unknown algorithm
 *       OID, an invalid key type for the requested algorithm, an unsupported
 *       parameter combination, or a missing / misconfigured JCA provider.
 *   <li>{@link OperatorStreamException} &mdash; an {@link java.io.IOException} subclass
 *       thrown from inside an operator's {@code OutputStream.write} /
 *       {@code InputStream.read} when the streaming method's signature only
 *       permits {@code IOException}.
 *   <li>{@link RuntimeOperatorException} &mdash; the unchecked variant used when an
 *       operator method has no {@code throws} clause to declare a checked exception
 *       on (for example methods overriding {@code Closeable.close()}).
 * </ul>
 * The original underlying failure, when there is one, is available via {@link #getCause()}.
 */
public class OperatorException
    extends Exception
{
    private static final long serialVersionUID = 1L;

    /**
     * Construct an exception with the supplied diagnostic message and the underlying cause
     * (typically a {@link java.security.GeneralSecurityException}, {@link java.io.IOException},
     * or lightweight {@code org.bouncycastle.crypto.CryptoException}) that triggered the failure.
     *
     * @param msg   diagnostic message describing the failure.
     * @param cause the underlying exception that triggered the failure, or {@code null} if
     *              this exception originates the failure itself.
     */
    public OperatorException(String msg, Throwable cause)
    {
        super(msg, cause);
    }

    /**
     * Construct an exception with the supplied diagnostic message and no underlying cause.
     *
     * @param msg diagnostic message describing the failure.
     */
    public OperatorException(String msg)
    {
        super(msg);
    }
}
