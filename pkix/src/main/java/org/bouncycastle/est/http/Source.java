package org.bouncycastle.est.http;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface Source<T>
{
    InputStream getInputStream() throws IOException;
    OutputStream getOutputStream() throws IOException;
    T getSession();
    void close() throws IOException;
}
