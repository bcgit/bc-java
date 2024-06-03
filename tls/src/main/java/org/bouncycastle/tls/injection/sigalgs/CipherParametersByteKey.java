package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.crypto.CipherParameters;

public interface CipherParametersByteKey
{
    byte[] byteKey(CipherParameters params);
}
