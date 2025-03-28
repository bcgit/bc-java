package org.bouncycastle.openpgp.api.exception;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;

/**
 * Exception representing an unusable or invalid {@link org.bouncycastle.openpgp.api.OpenPGPKey}
 * or {@link OpenPGPCertificate}.
 * Note: The term "key" is used to refer to both a certificate and a key.
 */
public class OpenPGPKeyException
        extends PGPException
{
    private final OpenPGPCertificate key;
    private final OpenPGPCertificate.OpenPGPComponentKey componentKey;

    private OpenPGPKeyException(OpenPGPCertificate key,
                                OpenPGPCertificate.OpenPGPComponentKey componentKey,
                                String message)
    {
        super(message);
        this.key = key;
        this.componentKey = componentKey;
    }

    /**
     * Something is wrong with a key or certificate in general (no particular subkey).
     *
     * @param key certificate or key
     * @param message message
     */
    public OpenPGPKeyException(OpenPGPCertificate key, String message)
    {
        this(key, null, message);
    }

    /**
     * Something is wrong with an individual component key of a key or certificate.
     *
     * @param componentKey component key
     * @param message message
     */
    public OpenPGPKeyException(OpenPGPCertificate.OpenPGPComponentKey componentKey, String message)
    {
        this(componentKey.getCertificate(), componentKey, message);
    }

    /**
     * Return the problematic key or certificate.
     *
     * @return key or certificate
     */
    public OpenPGPCertificate getKey()
    {
        return key;
    }

    /**
     * Return the problematic component key.
     * Might be null, if the problem affects the entire key or certificate.
     *
     * @return component key
     */
    public OpenPGPCertificate.OpenPGPComponentKey getComponentKey()
    {
        return componentKey;
    }
}
