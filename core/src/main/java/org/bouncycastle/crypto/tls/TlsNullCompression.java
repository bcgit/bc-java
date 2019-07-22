package org.bouncycastle.crypto.tls;

import java.io.OutputStream;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public class TlsNullCompression
    implements TlsCompression
{
    public OutputStream compress(OutputStream output)
    {
        return output;
    }

    public OutputStream decompress(OutputStream output)
    {
        return output;
    }
}
