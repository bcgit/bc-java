package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;

import java.security.Provider;

public class JcaCFBSecretKeyEncryptorFactory
        implements PBESecretKeyEncryptorFactory
{
    private final int symmetricKeyAlgorithm;
    private final int iterationCount;
    private JcaPGPDigestCalculatorProviderBuilder digestCalcProviderBuilder =
        new JcaPGPDigestCalculatorProviderBuilder();
    private JcePBESecretKeyEncryptorBuilder encBuilder;

    public JcaCFBSecretKeyEncryptorFactory(int symmetricKeyAlgorithm, int iterationCount)
        throws PGPException
    {
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.iterationCount = iterationCount;
        encBuilder = builder();
    }

    public JcaCFBSecretKeyEncryptorFactory setProvider(Provider provider)
        throws PGPException
    {
        digestCalcProviderBuilder.setProvider(provider);
        encBuilder = builder();
        return this;
    }

    private JcePBESecretKeyEncryptorBuilder builder()
        throws PGPException
    {
        return new JcePBESecretKeyEncryptorBuilder(
            symmetricKeyAlgorithm,
            digestCalcProviderBuilder.build().get(HashAlgorithmTags.SHA1),
            iterationCount
        );
    }

    @Override
    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket)
    {
        if (passphrase == null)
        {
            return null;
        }
        return encBuilder.build(passphrase);
    }
}
