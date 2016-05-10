package com.github.gv2011.bcasn.crypto.tls;

import java.io.OutputStream;

public interface TlsCompression
{
    OutputStream compress(OutputStream output);

    OutputStream decompress(OutputStream output);
}
