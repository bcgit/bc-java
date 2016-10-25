package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Basic interface for an SRP-6 server implementation.
 */
public interface TlsSRP6Server
{
    /**
     * Generates the server's credentials that are to be sent to the client.
     * @return The server's public value to the client
     */
    BigInteger generateServerCredentials();

    /**
     * Processes the client's credentials. If valid the shared secret is generated and returned.
     * @param clientA The client's credentials
     * @return A shared secret BigInteger
     * @throws IOException If client's credentials are invalid
     */
    BigInteger calculateSecret(BigInteger clientA) throws IOException;
}
