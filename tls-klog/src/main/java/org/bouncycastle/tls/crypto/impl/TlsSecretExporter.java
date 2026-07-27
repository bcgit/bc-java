package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Copies the raw bytes out of a {@link TlsSecret} for the RFC 9850 key log.
 * <p>
 * A {@link TlsSecret} deliberately offers no way to read its value: {@link TlsSecret#extract()}
 * takes the value and leaves the secret dead, which is no use to a bystander such as the key log.
 * {@link AbstractTlsSecret} does keep a package-private copier for the crypto layer's own use, and
 * this class is the one thing in the <code>bctls-klog</code> build that reaches it from outside the
 * package.
 * <p>
 * It exists only in that build. Its presence in a jar means that jar can disclose live connection
 * secrets, which is the whole point of <code>bctls-klog</code> and the reason it is a separate
 * artifact from <code>bctls</code>. Nothing else should call it.
 */
public abstract class TlsSecretExporter
{
    /**
     * Return a copy of the bytes of the given secret.
     *
     * @param secret the secret to copy; may be null.
     * @return the secret's bytes, or null if there are none to be had &mdash; the secret was null,
     *         has already been extracted or destroyed, or comes from a {@link TlsSecret}
     *         implementation outside this crypto layer, which keeps its value beyond reach.
     */
    public static byte[] exportSecret(TlsSecret secret)
    {
        if (secret instanceof AbstractTlsSecret)
        {
            return ((AbstractTlsSecret)secret).copyData();
        }

        return null;
    }
}
