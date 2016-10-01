package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Basic interface for an SRP-6 client implementation.
 */
public interface TlsSRP6Client
{
    /**
     * Generates the secret S given the server's credentials
     * @param serverB The server's credentials
     * @return Client's verification message for the server
     * @throws IOException If server's credentials are invalid
     */
    BigInteger calculateSecret(BigInteger serverB)
        throws IOException;

    /**
     * Generates client's credentials given the client's salt, identity and password
     * @param salt The salt used in the client's verifier.
     * @param identity The user's identity (eg. username)
     * @param password The user's password
     * @return Client's public value to send to server
     */
    BigInteger generateClientCredentials(byte[] salt, byte[] identity, byte[] password);
}
