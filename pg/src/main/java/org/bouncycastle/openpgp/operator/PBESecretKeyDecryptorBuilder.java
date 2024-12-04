package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PBESecretKeyDecryptorBuilder
{
    PBESecretKeyDecryptor build(char[] passphrase)
            throws PGPException;
}
