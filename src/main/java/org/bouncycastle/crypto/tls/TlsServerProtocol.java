package org.bouncycastle.crypto.tls;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class TlsServerProtocol extends TlsProtocol {

    public TlsServerProtocol(InputStream is, OutputStream os, SecureRandom sr) {
        super(is, os, sr);
    }
}
