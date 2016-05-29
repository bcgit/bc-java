package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public interface TlsSecret
{
    void export(OutputStream outputStream) throws IOException;
}
