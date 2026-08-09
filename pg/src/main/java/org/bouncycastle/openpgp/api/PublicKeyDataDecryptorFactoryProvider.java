package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;

/**
 * Provider of {@link PublicKeyDataDecryptorFactory} instances for secret keys whose private key material
 * BC cannot use directly - most importantly keys marked
 * {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_EXTERNAL} because they live on a hardware token.
 * <p>
 * Register an implementation with
 * {@link OpenPGPMessageProcessor#addPublicKeyDataDecryptorFactoryProvider(PublicKeyDataDecryptorFactoryProvider)}
 * to let the high-level API decrypt messages addressed to such a key.
 * <p>
 * This interface lives in the <code>api</code> package rather than in <code>operator</code> because it is
 * expressed in terms of the high-level {@link OpenPGPKey} and {@link KeyPassphraseProvider} types, which
 * are themselves layered on top of <code>operator</code>.
 */
public interface PublicKeyDataDecryptorFactoryProvider
{
    /**
     * Return a {@link PublicKeyDataDecryptorFactory} for the given secret key, or <code>null</code> if
     * this provider cannot serve that key - for example because no matching device is present. Returning
     * <code>null</code> lets the caller try the next registered provider, so it is the right answer for
     * "not mine"; throw a {@link PGPException} only when the key <em>is</em> ours and something went
     * wrong.
     *
     * @param secretKey secret key the message was encrypted to
     * @param passphraseProvider callback supplying the key passphrase, or a device PIN
     * @return a decryptor factory, or <code>null</code> if this provider cannot serve the key
     * @throws PGPException if the key is one this provider handles but a factory cannot be built
     */
    PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
        OpenPGPKey.OpenPGPSecretKey secretKey,
        KeyPassphraseProvider passphraseProvider)
        throws PGPException;
}
