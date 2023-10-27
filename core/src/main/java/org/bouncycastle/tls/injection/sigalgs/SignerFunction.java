package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

public interface SignerFunction {
    byte[] sign(JcaTlsCrypto crypto, byte[] data, byte[] key) throws Exception;
}
