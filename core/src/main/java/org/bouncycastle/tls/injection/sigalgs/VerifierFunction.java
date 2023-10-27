package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.DigitallySigned;

public interface VerifierFunction {
    boolean verify(byte[] message, byte[] publicKey, DigitallySigned signature);
}
