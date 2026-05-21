package org.bouncycastle.operator;

/**
 * Unchecked variant of {@link OperatorException} used when an operator method has no
 * {@code throws} clause to declare a checked exception on.
 * <p>
 * The streaming operator interfaces in this package extend {@link java.io.OutputStream}
 * / {@link java.io.InputStream} / {@link java.io.Closeable}, whose method signatures
 * &mdash; in particular {@code close()} and the no-args end-of-stream finalisers used
 * by some calculators &mdash; either don't declare {@code throws IOException} at all,
 * or are inherited from interfaces whose contract precludes additional checked
 * exceptions. When a cryptographic failure surfaces from one of those points, the
 * operator wraps it in a {@code RuntimeOperatorException} so it can still propagate
 * to the caller without violating the signature. The original failure is available
 * via {@link #getCause()}.
 */
public class RuntimeOperatorException
    extends RuntimeException
{
    private static final long serialVersionUID = 1L;

    /**
     * Construct an exception with the supplied diagnostic message and no underlying cause.
     *
     * @param msg diagnostic message describing the failure.
     */
    public RuntimeOperatorException(String msg)
    {
        super(msg);
    }

    /**
     * Construct an exception with the supplied diagnostic message and the underlying cause.
     *
     * @param msg   diagnostic message describing the failure.
     * @param cause the underlying exception that triggered the failure, or {@code null}.
     */
    public RuntimeOperatorException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
