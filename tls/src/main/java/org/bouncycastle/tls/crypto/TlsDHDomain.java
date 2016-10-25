package org.bouncycastle.tls.crypto;

/**
 * Domain interface to service factory for creating Diffie-Hellman operators.
 */
public interface TlsDHDomain
{
    /**
     * Return an agreement operator suitable for ephemeral Diffie-Hellman.
     *
     * @return a key agreement operator.
     */
    TlsAgreement createDH();
}
