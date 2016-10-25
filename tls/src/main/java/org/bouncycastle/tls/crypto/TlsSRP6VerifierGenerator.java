package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/**
 * Base interface for a generator for SRP-6 verifiers.
 */
public interface TlsSRP6VerifierGenerator
{
    /**
     * Creates a new SRP-6 verifier value.
     *
     * @param salt The salt to use, generally should be large and random
     * @param identity The user's identifying information (eg. username)
     * @param password The user's password
     * @return A new verifier for use in future SRP authentication
     */
    BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password);
}
