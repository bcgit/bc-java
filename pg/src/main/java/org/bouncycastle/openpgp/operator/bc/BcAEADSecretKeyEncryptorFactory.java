package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;

/**
 * Return a factory for {@link PBESecretKeyEncryptor} instances which protect the secret key material by deriving
 * a key-encryption-key using {@link org.bouncycastle.bcpg.S2K#ARGON_2} S2K and apply
 * that key using {@link org.bouncycastle.bcpg.SecretKeyPacket#USAGE_AEAD}.
 * <p>
 * This particular factory uses OCB + AES256 for secret key protection and requires 2GiB of RAM
 * for the Argon2 key derivation (see {@link S2K.Argon2Params#universallyRecommendedParameters()}).
 */
public class BcAEADSecretKeyEncryptorFactory
        extends PBESecretKeyEncryptorFactory
{
    @Override
    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket)
    {
        if (passphrase == null)
        {
            return null;
        }
        return new BcAEADSecretKeyEncryptorBuilder(
                AEADAlgorithmTags.OCB,
                SymmetricKeyAlgorithmTags.AES_256,
                S2K.Argon2Params.universallyRecommendedParameters())
                .build(passphrase, pubKeyPacket);
    }
}
