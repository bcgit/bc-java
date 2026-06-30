package org.bouncycastle.operator;

import java.io.IOException;

/**
 * Thrown from inside an operator's streaming method when an underlying cryptographic
 * failure occurs and the surrounding signature only permits an {@link IOException}.
 * <p>
 * Operators that expose stream-shaped interfaces &mdash; for example
 * {@code DigestCalculator.getOutputStream()},
 * {@code MacCalculator.getOutputStream()},
 * {@code ContentSigner.getOutputStream()},
 * {@code OutputEncryptor.getOutputStream(OutputStream)} &mdash; have their
 * {@code OutputStream.write} / {@code InputStream.read} methods constrained by the
 * {@code throws IOException} declared on {@link java.io.OutputStream} /
 * {@link java.io.InputStream}. A cryptographic failure that surfaces from inside one of
 * those calls (cipher state corruption, MAC tag mismatch, padding error, etc.) is
 * wrapped in an {@code OperatorStreamException} so it can propagate out of the stream
 * method via the {@code IOException} type, while still carrying the original failure on
 * its cause chain for diagnosis via {@link #getCause()}.
 */
public class OperatorStreamException
    extends IOException
{
    private static final long serialVersionUID = 1L;

    /**
     * Construct an exception with the supplied diagnostic message and the underlying cause
     * &mdash; typically a {@link java.security.GeneralSecurityException} subclass or a
     * lightweight {@code org.bouncycastle.crypto.CryptoException} from inside the operator.
     *
     * @param msg   diagnostic message describing the failure.
     * @param cause the underlying exception that triggered the failure, or {@code null}.
     */
    public OperatorStreamException(String msg, Throwable cause)
    {
        super(msg);
        if (cause != null)
        {
            initCause(cause);
        }
    }
}
