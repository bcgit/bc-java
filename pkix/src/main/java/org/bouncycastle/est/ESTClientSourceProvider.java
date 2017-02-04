package org.bouncycastle.est;

import java.io.IOException;
import java.net.Socket;

/**
 * ESTClientSourceProvider, implementations of this are expected to provide custom
 * wrapping of an existing plain socket and return a source.
 */
public interface ESTClientSourceProvider
{
    Source wrapSocket(Socket plainSocket, String host, int port)
        throws IOException;
}
