package org.bouncycastle.est;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Used to Wrap a socket and to provide access to the underlying session.
 *
 * @param <T> Is the type of session that is returned. Eg For JSSE would be SSLSession.
 */
public interface Source<T>
{
    InputStream getInputStream()
        throws IOException;

    OutputStream getOutputStream()
        throws IOException;

    T getSession();

    void close()
        throws IOException;

}
