package org.bouncycastle.est.http;


import java.net.Socket;

/**
 * ESTHttpHijacker can take control of the socket after the initial connection
 * has been sent so that other protocol can be negotiated outside of the normal
 * request / response flow.
 */
public interface ESTHttpHijacker
{
    ESTHttpResponse hijack(ESTHttpRequest req, Socket sock)
        throws Exception;
}
