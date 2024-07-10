package org.bouncycastle.tls.injection.sigalgs;

import java.security.PublicKey;

public interface PublicKeyToByteKey
{
    byte[] byteKey(PublicKey key);
}
