package org.bouncycastle.tls.crypto;

/**
 * Interface for MAC services based on HMAC.
 */
public interface TlsHMAC
    extends TlsMAC
{
    /**
     * Return the internal block size for the message digest underlying this HMAC service.
     *
     * @return the internal block size for the digest (in bytes).
     */
    int getInternalBlockSize();
}
