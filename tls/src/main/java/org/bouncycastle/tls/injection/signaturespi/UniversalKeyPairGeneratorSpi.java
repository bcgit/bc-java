package org.bouncycastle.tls.injection.signaturespi;


import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.Strings;

public class UniversalKeyPairGeneratorSpi
        extends java.security.KeyPairGenerator
{

    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    RSAEngine engine;

    public UniversalKeyPairGeneratorSpi()
    {
        super("TLS INJECTION MECHANISM SIGNATURE ALGORITHMS");
        this.engine = new RSAEngine();
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
        int x=5;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            //param = new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.sha2_256s);

            //engine.init(param);
            initialised = true;
        }

        /*engine.
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        SPHINCSPlusPublicKeyParameters pub = (SPHINCSPlusPublicKeyParameters)pair.getPublic();
        SPHINCSPlusPrivateKeyParameters priv = (SPHINCSPlusPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCSPHINCSPlusPublicKey(pub), new BCSPHINCSPlusPrivateKey(priv));*/
        return null;
    }

}
