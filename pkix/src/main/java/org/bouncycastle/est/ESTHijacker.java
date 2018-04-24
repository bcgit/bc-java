package org.bouncycastle.est;


import java.io.IOException;

/**
 * ESTHijacker can take control of the source after the initial http request
 * has been sent and a response received.
 * A hijacker is then able to send more request or be able to modify the response before returning a response
 * to the original caller.
 * <p>
 * See DigestAuth and BasicAuth.
 */
public interface ESTHijacker
{
    ESTResponse hijack(ESTRequest req, Source sock)
        throws IOException;
}
