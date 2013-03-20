package org.bouncycastle.crypto.tls;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class TlsClientProtocol extends TlsProtocol {

    public TlsClientProtocol(InputStream is, OutputStream os) {
        super(is, os);
    }

    public TlsClientProtocol(InputStream is, OutputStream os, SecureRandom sr) {
        super(is, os, sr);
    }
}
