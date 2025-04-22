package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

/**
 * Provider for {@link PBESecretKeyDecryptorBuilder} instances.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation of {@link PBESecretKeyDecryptorBuilder} (builder for objects that can unlock encrypted
 * secret keys) to return.
 */
public interface PBESecretKeyDecryptorBuilderProvider
{
    PBESecretKeyDecryptorBuilder provide()
            throws PGPException;
}
