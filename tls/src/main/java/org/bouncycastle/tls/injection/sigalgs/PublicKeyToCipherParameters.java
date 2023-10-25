package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidKeyException;
import java.security.PublicKey;

public interface PublicKeyToCipherParameters {
    CipherParameters parameters(PublicKey publicKey) throws InvalidKeyException;
}