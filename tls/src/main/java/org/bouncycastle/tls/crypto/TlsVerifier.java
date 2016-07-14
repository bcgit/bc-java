package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.DigitallySigned;

public interface TlsVerifier
{
    boolean verifySignature(DigitallySigned signature, byte[] hash) throws IOException;
}
