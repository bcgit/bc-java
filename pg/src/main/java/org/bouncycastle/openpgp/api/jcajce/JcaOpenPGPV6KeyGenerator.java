package org.bouncycastle.openpgp.api.jcajce;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPV6KeyGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaAEADSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaCFBSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;

import java.security.Provider;
import java.util.Date;

public class JcaOpenPGPV6KeyGenerator
        extends OpenPGPV6KeyGenerator
{

    public JcaOpenPGPV6KeyGenerator(Provider provider)
            throws PGPException
    {
        this(new Date(), provider);
    }

    public JcaOpenPGPV6KeyGenerator(Date creationTime, Provider provider)
            throws PGPException
    {
        this(DEFAULT_SIGNATURE_HASH_ALGORITHM, creationTime, true, provider);
    }

    public JcaOpenPGPV6KeyGenerator(int signatureHashAlgorithm, Provider provider)
            throws PGPException
    {
        this(signatureHashAlgorithm, new Date(), true, provider);
    }

    /**
     * Create a new OpenPGP key generator for v6 keys.
     *
     * @param signatureHashAlgorithm ID of the hash algorithm used for signatures on the key
     * @param creationTime           creation time of the key and signatures
     */
    public JcaOpenPGPV6KeyGenerator(int signatureHashAlgorithm, Date creationTime, boolean aeadProtection, Provider provider)
            throws PGPException
    {
        super(
                new JcaPGPKeyPairGeneratorProvider()
                        .setProvider(provider),
                new JcaPGPContentSignerBuilderProvider(signatureHashAlgorithm)
                        .setSecurityProvider(provider),
                new JcaPGPDigestCalculatorProviderBuilder()
                        .setProvider(provider)
                        .build(),
                keyEncryptorFactory(provider, aeadProtection),
                new JcaKeyFingerprintCalculator(),
                creationTime);
    }

    private static PBESecretKeyEncryptorFactory keyEncryptorFactory(Provider provider, boolean aeadProtection)
            throws PGPException
    {
        if (aeadProtection)
        {
            return new JcaAEADSecretKeyEncryptorFactory().setProvider(provider);
        }
        else
        {
            return new JcaCFBSecretKeyEncryptorFactory().setProvider(provider);

        }
    }
}
