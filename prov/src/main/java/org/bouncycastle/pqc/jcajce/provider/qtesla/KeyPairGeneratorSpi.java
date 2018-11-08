package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static final Map catLookup = new HashMap();

    static
    {
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I), QTESLASecurityCategory.HEURISTIC_I);
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SIZE), QTESLASecurityCategory.HEURISTIC_III_SIZE);
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SPEED), QTESLASecurityCategory.HEURISTIC_III_SPEED);
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I), QTESLASecurityCategory.PROVABLY_SECURE_I);
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III), QTESLASecurityCategory.PROVABLY_SECURE_III);
    }

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

        param = new QTESLAKeyGenerationParameters((Integer)catLookup.get(qteslaParams.getSecurityCategory()), random);

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_I, random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        QTESLAPublicKeyParameters pub = (QTESLAPublicKeyParameters)pair.getPublic();
        QTESLAPrivateKeyParameters priv = (QTESLAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCqTESLAPublicKey(pub), new BCqTESLAPrivateKey(priv));
    }
}
