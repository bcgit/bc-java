package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.api.OpenPGPKey;

public abstract class BcExternalPublicKeyDataDecryptorFactory
        extends BcPublicKeyDataDecryptorFactory
{
    OpenPGPKey.OpenPGPSecretKey secretKey;

    public BcExternalPublicKeyDataDecryptorFactory(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
    {
        super(unlock(secretKey));
        this.secretKey = secretKey;
    }

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
            return new PGPKeyPair(secretKey.getPGPPublicKey(), null);
        }
        return privKey.getKeyPair();
    }

    @Override
    protected PublicKeyCryptoCallback getCryptoCallback()
    {
        // If we have a software-key available, we can skip costly hardware decryption
        return !secretKey.getPGPSecretKey().isExternalKey() ?
                super.getCryptoCallback() : // software-based key
                getExternalKeyCryptoCallback(); // hardware-based key
    }

    public abstract PublicKeyCryptoCallback getExternalKeyCryptoCallback();
}
