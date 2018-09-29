package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private QTESLAKeyGenerationParameters param;
    private QTESLAKeyPairGenerator engine = new QTESLAKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("qTESLA");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof QTESLAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a QTESLAParameterSpec");
        }

        QTESLAParameterSpec qteslaParams = (QTESLAParameterSpec)params;

        param = new QTESLAKeyGenerationParameters(qteslaParams.getSecurityCategory(), random);

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new QTESLAKeyGenerationParameters(QTESLAParameterSpec.PROVABLY_SECURE_I, random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        QTESLAPublicKeyParameters pub = (QTESLAPublicKeyParameters)pair.getPublic();
        QTESLAPrivateKeyParameters priv = (QTESLAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCqTESLAPublicKey(pub), new BCqTESLAPrivateKey(priv));
    }
}
