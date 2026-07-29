package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;

/**
 * Provider class for {@link PublicKeyDataDecryptorFactory} instances.
 */
public interface PublicKeyDataDecryptorFactoryProvider
{
    /**
     * Returns a {@link PublicKeyDataDecryptorFactory} for the given {@link PGPSecretKey}.
     * If for any reason the provider cannot provide a factory, it may return null.
     *
     * @param secretKey secret key
     * @param passphraseProvider passphrase provider
     * @return {@link PublicKeyDataDecryptorFactory}
     */
    PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            KeyPassphraseProvider passphraseProvider);
}
