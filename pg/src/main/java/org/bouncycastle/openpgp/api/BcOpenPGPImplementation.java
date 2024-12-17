package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
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
import org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcCFBSecretKeyEncryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory;

import java.io.InputStream;

public class BcOpenPGPImplementation
        extends OpenPGPImplementation
{
    @Override
    public PGPObjectFactory pgpObjectFactory(InputStream packetInputStream)
    {
        return new BcPGPObjectFactory(packetInputStream);
    }

    @Override
    public PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider()
    {
        return new BcPGPContentVerifierBuilderProvider();
    }

    @Override
    public PBESecretKeyDecryptorBuilderProvider pbeSecretKeyDecryptorBuilderProvider()
    {
        return new BcPBESecretKeyDecryptorBuilderProvider();
    }

    @Override
    public PGPDataEncryptorBuilder pgpDataEncryptorBuilder(int symmetricKeyAlgorithm)
    {
        return new BcPGPDataEncryptorBuilder(symmetricKeyAlgorithm);
    }

    @Override
    public PublicKeyKeyEncryptionMethodGenerator publicKeyKeyEncryptionMethodGenerator(PGPPublicKey encryptionSubkey)
    {
        return new BcPublicKeyKeyEncryptionMethodGenerator(encryptionSubkey);
    }

    @Override
    public PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] messagePassphrase)
    {
        return new BcPBEKeyEncryptionMethodGenerator(messagePassphrase);
    }

    @Override
    public PBEKeyEncryptionMethodGenerator pbeKeyEncryptionMethodGenerator(char[] messagePassphrase, S2K.Argon2Params argon2Params)
    {
        return new BcPBEKeyEncryptionMethodGenerator(messagePassphrase, argon2Params);
    }

    @Override
    public PGPContentSignerBuilder pgpContentSignerBuilder(int publicKeyAlgorithm, int hashAlgorithm)
    {
        return new BcPGPContentSignerBuilder(publicKeyAlgorithm, hashAlgorithm);
    }

    @Override
    public PBEDataDecryptorFactory pbeDataDecryptorFactory(char[] messagePassphrase)
            throws PGPException
    {
        return new BcPBEDataDecryptorFactory(messagePassphrase, pgpDigestCalculatorProvider());
    }

    @Override
    public SessionKeyDataDecryptorFactory sessionKeyDataDecryptorFactory(PGPSessionKey sessionKey)
    {
        return new BcSessionKeyDataDecryptorFactory(sessionKey);
    }

    @Override
    public PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory(PGPPrivateKey decryptionKey)
    {
        return new BcPublicKeyDataDecryptorFactory(decryptionKey);
    }

    @Override
    public PGPDigestCalculatorProvider pgpDigestCalculatorProvider()
            throws PGPException
    {
        return new BcPGPDigestCalculatorProvider();
    }

    @Override
    public PGPKeyPairGeneratorProvider pgpKeyPairGeneratorProvider()
    {
        return new BcPGPKeyPairGeneratorProvider();
    }

    @Override
    public PGPContentSignerBuilderProvider pgpContentSignerBuilderProvider(int hashAlgorithmId)
    {
        return new BcPGPContentSignerBuilderProvider(hashAlgorithmId);
    }

    @Override
    public KeyFingerPrintCalculator keyFingerPrintCalculator()
    {
        return new BcKeyFingerprintCalculator();
    }

    @Override
    public PBESecretKeyEncryptorFactory pbeSecretKeyEncryptorFactory(boolean aead)
    {
        if (aead)
        {
            return new BcAEADSecretKeyEncryptorFactory();
        }
        else
        {
            return new BcCFBSecretKeyEncryptorFactory();
        }
    }
}
