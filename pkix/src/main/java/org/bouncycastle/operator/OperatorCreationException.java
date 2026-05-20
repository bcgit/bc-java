package org.bouncycastle.operator;

/**
 * Thrown by an operator <em>builder</em> when it cannot produce the requested operator.
 * <p>
 * Operator builders &mdash; for example {@code JcaContentSignerBuilder},
 * {@code BcRSAContentSignerBuilder}, {@code JcaDigestCalculatorProviderBuilder},
 * {@code JceCMSContentEncryptorBuilder} &mdash; assemble a configured operator
 * ({@code ContentSigner}, {@code DigestCalculator}, etc.) from caller-supplied inputs:
 * an algorithm identifier or name, a key, a {@code SecureRandom}, optional JCA provider,
 * and so on. Construction can fail before any data has been processed, for reasons such as:
 * <ul>
 *   <li>unknown or unsupported algorithm OID / name;</li>
 *   <li>key type incompatible with the requested algorithm (e.g. an RSA key passed to an
 *       EC signer);</li>
 *   <li>invalid or unsupported parameter combination (key size, hash, PSS salt length, etc.);</li>
 *   <li>the underlying JCA provider is missing, misconfigured, or rejects the algorithm
 *       (manifests as a {@code NoSuchAlgorithmException} / {@code NoSuchProviderException}
 *       / {@code InvalidKeyException} on the cause chain);</li>
 *   <li>a lightweight engine could not be initialised (manifests as a
 *       {@code CryptoException} on the cause chain).</li>
 * </ul>
 * Inspect {@link #getCause()} for the underlying exception when one is supplied.
 */
public class OperatorCreationException
    extends OperatorException
{
    private static final long serialVersionUID = 1L;

    /**
     * Construct an exception with the supplied diagnostic message and the underlying cause
     * (typically a {@link java.security.GeneralSecurityException} subclass or a lightweight
     * {@code org.bouncycastle.crypto.CryptoException}) returned by the JCA or lightweight
     * machinery the builder was driving.
     *
     * @param msg   diagnostic message describing what the builder was trying to do and why
     *              it failed.
     * @param cause the underlying exception that triggered the failure, or {@code null}.
     */
    public OperatorCreationException(String msg, Throwable cause)
    {
        super(msg, cause);
    }

    /**
     * Construct an exception with the supplied diagnostic message and no underlying cause.
     *
     * @param msg diagnostic message describing what the builder was trying to do and why
     *            it failed.
     */
    public OperatorCreationException(String msg)
    {
        super(msg);
    }
}
