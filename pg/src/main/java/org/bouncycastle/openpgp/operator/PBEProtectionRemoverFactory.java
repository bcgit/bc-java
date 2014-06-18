package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PBEProtectionRemoverFactory
{
    PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException;
}
