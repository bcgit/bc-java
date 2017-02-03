package org.bouncycastle.est;


/**
 * ESTHttpHijacker can take control of the socket after the initial connection
 * has been sent so that other protocol can be negotiated outside of the normal
 * request / response flow.
 */
public interface ESTHttpHijacker
{
    ESTResponse hijack(ESTRequest req, Source sock)
        throws Exception;
}
