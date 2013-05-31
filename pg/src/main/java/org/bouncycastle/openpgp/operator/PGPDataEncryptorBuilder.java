package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.openpgp.PGPException;

public interface PGPDataEncryptorBuilder
{
    int getAlgorithm();

    PGPDataEncryptor build(byte[] keyBytes)
        throws PGPException;

    SecureRandom getSecureRandom();
}
