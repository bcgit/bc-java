package org.bouncycastle.tls.injection.sigalgs;

import java.security.PublicKey;

public interface PublicKeyToEncodedKey {
    byte[] encodedKey(PublicKey key);
}
