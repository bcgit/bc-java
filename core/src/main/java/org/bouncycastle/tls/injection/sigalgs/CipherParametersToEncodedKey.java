package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.crypto.CipherParameters;

public interface CipherParametersToEncodedKey {
    byte[] encodedKey(CipherParameters params);
}
