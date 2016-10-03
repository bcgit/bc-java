package org.bouncycastle.tls.crypto;

/**
 * Domain interface to service factory for creating Elliptic-Curve (EC) based operators.
 */
public interface TlsECDomain
{
    /**
     * Return an agreement operator suitable for ephemeral EC Diffie-Hellman.
     *
     * @return a key agreement operator.
     */
    TlsAgreement createECDH();
}
