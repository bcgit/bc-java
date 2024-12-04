package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPSessionKey;

/**
 * Factory for {@link PGPDataDecryptor} objects that use a {@link PGPSessionKey} to decrypt the content of an
 * OpenPGP message.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation to use for message decryption.
 */
public interface SessionKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    PGPSessionKey getSessionKey();
}
