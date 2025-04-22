package org.bouncycastle.openpgp.api.jcajce;

import java.io.InputStream;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaAEADSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaCFBSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder;

/**
 * Implementation of {@link OpenPGPImplementation} using the JCA/JCE implementation of OpenPGP classes.
 */
public class JcaOpenPGPImplementation
        extends OpenPGPImplementation
{
    private final Provider provider;
    private final SecureRandom secureRandom;

    public JcaOpenPGPImplementation()
    {
        this(new BouncyCastleProvider(), CryptoServicesRegistrar.getSecureRandom());
    }

    public JcaOpenPGPImplementation(Provider provider, SecureRandom secureRandom)
    {
        this.provider = provider;
        this.secureRandom = secureRandom;
    }

    @Override
    public PGPObjectFactory pgpObjectFactory(InputStream packetInputStream)
    {
        return new JcaPGPObjectFactory(packetInputStream)
                .setThrowForUnknownCriticalPackets(true);
    }

    @Override
    public PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider()
    {
        JcaPGPContentVerifierBuilderProvider p = new JcaPGPContentVerifierBuilderProvider();
        p.setProvider(provider);
        return p;
    }

    @Override
    public PBESecretKeyDecryptorBuilderProvider pbeSecretKeyDecryptorBuilderProvider()
    {
        JcaPGPDigestCalculatorProviderBuilder dp = new JcaPGPDigestCalculatorProviderBuilder();
        dp.setProvider(provider);
        JcePBESecretKeyDecryptorBuilderProvider p = new JcePBESecretKeyDecryptorBuilderProvider(dp)
                .setProvider(provider);
        return p;
    }

    @Override
    public PGPDataEncryptorBuilder pgpDataEncryptorBuilder(int symmetricKeyAlgorithm)
    {
        JcePGPDataEncryptorBuilder b = new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm);
        b.setProvider(provider);
        b.setSecureRandom(secureRandom);
        return b;
    }

    @Override
    public PublicKeyKeyEncryptionMethodGenerator publicKeyKeyEncryptionMethodGenerator(PGPPublicKey encryptionSubkey)
    {
        JcePublicKeyKeyEncryptionMethodGenerator g = new JcePublicKeyKeyEncryptionMethodGenerator(encryptionSubkey);
        g.setProvider(provider);
        g.setSecureRandom(secureRandom);
        return g;
    }

    @Override
    public PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] messagePassphrase)
    {
        JcePBEKeyEncryptionMethodGenerator g = new JcePBEKeyEncryptionMethodGenerator(messagePassphrase);
        g.setProvider(provider);
        g.setSecureRandom(secureRandom);
        return g;
    }

    @Override
    public PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] messagePassphrase, S2K.Argon2Params argon2Params)
    {
        JcePBEKeyEncryptionMethodGenerator g = new JcePBEKeyEncryptionMethodGenerator(messagePassphrase, argon2Params);
        g.setProvider(provider);
        g.setSecureRandom(secureRandom);
        return g;
    }

    @Override
    public PGPContentSignerBuilder pgpContentSignerBuilder(int publicKeyAlgorithm, int hashAlgorithm)
    {
        JcaPGPContentSignerBuilder b = new JcaPGPContentSignerBuilder(publicKeyAlgorithm, hashAlgorithm);
        b.setProvider(provider);
        b.setDigestProvider(provider);
        b.setSecureRandom(secureRandom);
        return b;
    }

    @Override
    public PBEDataDecryptorFactory pbeDataDecryptorFactory(char[] messagePassphrase)
            throws PGPException
    {
        return new JcePBEDataDecryptorFactoryBuilder(pgpDigestCalculatorProvider())
                .setProvider(provider)
                .build(messagePassphrase);
    }

    @Override
    public SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory(PGPSessionKey sessionKey)
    {
        return new JceSessionKeyDataDecryptorFactoryBuilder()
                .setProvider(provider)
                .build(sessionKey);
    }

    @Override
    public PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory(PGPPrivateKey decryptionKey)
    {
        return new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(provider)
                .setContentProvider(provider)
                .build(decryptionKey);
    }

    @Override
    public PGPDigestCalculatorProvider pgpDigestCalculatorProvider()
            throws PGPException
    {
        return new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(provider)
                .build();
    }

    @Override
    public PGPKeyPairGeneratorProvider pgpKeyPairGeneratorProvider()
    {
        return new JcaPGPKeyPairGeneratorProvider()
                .setProvider(provider)
                .setSecureRandom(secureRandom);
    }

    @Override
    public PGPContentSignerBuilderProvider pgpContentSignerBuilderProvider(int hashAlgorithmId)
    {
        return new JcaPGPContentSignerBuilderProvider(hashAlgorithmId)
                .setSecurityProvider(provider)
                .setDigestProvider(provider)
                .setSecureRandom(secureRandom);
    }

    @Override
    public KeyFingerPrintCalculator keyFingerPrintCalculator()
    {
        return new JcaKeyFingerprintCalculator()
                .setProvider(provider);
    }

    @Override
    public PBESecretKeyEncryptorFactory pbeSecretKeyEncryptorFactory(boolean aead)
        throws PGPException
    {
        if (aead)
        {
            return new JcaAEADSecretKeyEncryptorFactory()
                    .setProvider(provider);
        }
        else
        {
            return new JcaCFBSecretKeyEncryptorFactory(SymmetricKeyAlgorithmTags.AES_128, 0x60)
                    .setProvider(provider);
        }
    }

    @Override
    public PBESecretKeyEncryptorFactory pbeSecretKeyEncryptorFactory(boolean aead, int symmetricKeyAlgorithm, int iterationCount)
            throws PGPException
    {
        if (aead)
        {
            return new JcaAEADSecretKeyEncryptorFactory()
                    .setProvider(provider);
        }
        else
        {
            return new JcaCFBSecretKeyEncryptorFactory(symmetricKeyAlgorithm, iterationCount)
                    .setProvider(provider);
        }
    }
}
