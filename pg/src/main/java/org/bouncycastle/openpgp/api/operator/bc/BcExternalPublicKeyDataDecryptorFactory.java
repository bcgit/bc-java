package org.bouncycastle.openpgp.api.operator.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyCryptoCallback;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

/**
 * Base class for a {@link BcPublicKeyDataDecryptorFactory} whose private key material is held outside
 * the OpenPGP key - typically on a hardware token - as described by
 * <a href="https://datatracker.ietf.org/doc/draft-dkg-openpgp-external-secrets/">OpenPGP External Secret
 * Keys</a> and signalled by {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_EXTERNAL}.
 * <p>
 * All session-key recovery logic (packet parsing, length checks, the RFC 6637 / RFC 9580 KDF and key
 * unwrap) is inherited from {@link BcPublicKeyDataDecryptorFactory}; a subclass supplies only the raw
 * private-key operation by implementing {@link #getExternalKeyCryptoCallback()}.
 * <p>
 * Note that a secret key handled through this class need not actually be external: if the supplied key
 * does carry usable software key material, {@link #getCryptoCallback()} returns the inherited software
 * callback so the (much cheaper) in-process path is used instead.
 */
public abstract class BcExternalPublicKeyDataDecryptorFactory
    extends BcPublicKeyDataDecryptorFactory
{
    private final OpenPGPKey.OpenPGPSecretKey secretKey;

    /**
     * Create a decryptor factory for the given secret key.
     *
     * @param secretKey the (typically external) OpenPGP secret key
     * @throws PGPException if the key cannot be unlocked
     */
    public BcExternalPublicKeyDataDecryptorFactory(OpenPGPKey.OpenPGPSecretKey secretKey)
        throws PGPException
    {
        super(unlock(secretKey));
        this.secretKey = secretKey;
    }

    /**
     * Return the secret key this factory decrypts for.
     *
     * @return secret key
     */
    protected OpenPGPKey.OpenPGPSecretKey getSecretKey()
    {
        return secretKey;
    }

    private static PGPKeyPair unlock(OpenPGPKey.OpenPGPSecretKey secretKey)
        throws PGPException
    {
        OpenPGPKey.OpenPGPPrivateKey privKey = secretKey.unlock();
        if (privKey == null)
        {
            // external key: there is no private key packet to unlock, the public half is enough
            return new PGPKeyPair(secretKey.getPGPPublicKey(), null);
        }
        return privKey.getKeyPair();
    }

    @Override
    protected BcPublicKeyCryptoCallback getCryptoCallback()
    {
        // if software key material is available we can skip the costly hardware round trip
        if (!secretKey.getPGPSecretKey().isExternalKey())
        {
            return super.getCryptoCallback();
        }
        return getExternalKeyCryptoCallback();
    }

    /**
     * Return the callback routing the raw private-key operation to the external device.
     *
     * @return crypto callback for the externally-held key
     */
    public abstract BcPublicKeyCryptoCallback getExternalKeyCryptoCallback();
}
