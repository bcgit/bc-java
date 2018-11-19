package org.bouncycastle.tls;

/**
 * Processor interface for an SRP identity.
 */
public interface TlsSRPIdentity
{
    byte[] getSRPIdentity();

    byte[] getSRPPassword();
}
