package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

public interface TlsStreamVerifier
{
    OutputStream getOutputStream() throws IOException;

    boolean isVerified() throws IOException;
}
