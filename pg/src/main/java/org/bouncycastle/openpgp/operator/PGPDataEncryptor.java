package org.bouncycastle.openpgp.operator;

import java.io.OutputStream;

/**
 * A data encryptor, combining a cipher instance and an optional integrity check calculator.
 * <p>
 * {@link PGPDataEncryptor} instances are generally not constructed directly, but obtained from a
 * {@link PGPDataEncryptorBuilder}.
 * </p>
 */
public interface PGPDataEncryptor
{
    /**
     * Constructs an encrypting output stream that encrypts data using the underlying cipher of this
     * encryptor.
     * <p>
     * The cipher instance in this encryptor is used for all output streams obtained from this
     * method, so it should only be invoked once.
     * </p>
     * @param out the stream to wrap and write encrypted data to.
     * @return a cipher output stream appropriate to the type of this data encryptor.
     */
    OutputStream getOutputStream(OutputStream out);

    /**
     * Obtains the integrity check calculator configured for this encryptor instance.
     *
     * @return the integrity check calculator, or <code>null</code> if no integrity checking was
     *         configured.
     */
    PGPDigestCalculator getIntegrityCalculator();

    /**
     * Gets the block size of the underlying cipher used by this encryptor.
     *
     * @return the block size in bytes.
     */
    int getBlockSize();
}
