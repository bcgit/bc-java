package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;

import java.security.Provider;

public class JcaAEADSecretKeyEncryptorFactory
        extends PBESecretKeyEncryptorFactory
{
    private JcaAEADSecretKeyEncryptorBuilder builder = new JcaAEADSecretKeyEncryptorBuilder(
            AEADAlgorithmTags.OCB,
            SymmetricKeyAlgorithmTags.AES_256,
            S2K.Argon2Params.universallyRecommendedParameters());

    public JcaAEADSecretKeyEncryptorFactory setProvider(Provider provider)
    {
        builder.setProvider(provider);
        return this;
    }

    @Override
    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket)
    {
        if (passphrase == null)
        {
            return null;
        }
        return builder.build(passphrase, pubKeyPacket);
    }
}
