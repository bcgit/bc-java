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
import org.bouncycastle.util.Integers;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static final Map catLookup = new HashMap();

    static
    {
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_I));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_II), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_II));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_III));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_P_I), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_P_I));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_P_III), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_P_III));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_V), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_V));
        catLookup.put(QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_V_SIZE), Integers.valueOf(QTESLASecurityCategory.HEURISTIC_V_SIZE));
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

        param = new QTESLAKeyGenerationParameters(((Integer)catLookup.get(qteslaParams.getSecurityCategory())).intValue(), random);

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new QTESLAKeyGenerationParameters(QTESLASecurityCategory.HEURISTIC_P_III, random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        QTESLAPublicKeyParameters pub = (QTESLAPublicKeyParameters)pair.getPublic();
        QTESLAPrivateKeyParameters priv = (QTESLAPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCqTESLAPublicKey(pub), new BCqTESLAPrivateKey(priv));
    }
}
