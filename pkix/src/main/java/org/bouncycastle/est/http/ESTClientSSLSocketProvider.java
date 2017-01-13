package org.bouncycastle.est.http;

import java.net.Socket;

import javax.net.ssl.SSLSocket;

/**
 * ESTClientSSLSocketProvider implementations of this are expected to provide custom
 * wrapping of an existing plain socket that applies nuanced control over the SSLSocket.
 */
public interface ESTClientSSLSocketProvider
{
    public SSLSocket wrapSocket(Socket plainSocket, String host, int port)
        throws Exception;
}
