package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidKeyException;
import java.security.PrivateKey;

public interface PrivateKeyToCipherParameters {
    CipherParameters parameters(PrivateKey privateKey) throws InvalidKeyException;
}