package com.github.gv2011.bcasn.crypto.tls;

import java.io.OutputStream;

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
