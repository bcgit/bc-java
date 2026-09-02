package org.bouncycastle.pqc.jcajce.provider.lms;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.HSSKeyGenerationParameters;
import org.bouncycastle.crypto.generators.HSSKeyPairGenerator;
import org.bouncycastle.crypto.params.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.HSSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSParameterSpec;

public class LMSKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private KeyGenerationParameters param;
    private ASN1ObjectIdentifier treeDigest;
    private AsymmetricCipherKeyPairGenerator engine = new LMSKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public LMSKeyPairGeneratorSpi()
    {
        super("LMS");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        // what the JCA specifies here; it extends IllegalArgumentException, so catches still match
        throw new InvalidParameterException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof LMSKeyGenParameterSpec)
        {
            LMSKeyGenParameterSpec lmsParams = (LMSKeyGenParameterSpec)params;

            param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getLMSigParameters(), lmsParams.getLMOtsParameters()), random);

            engine = new LMSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSHSSKeyGenParameterSpec)
        {
            LMSKeyGenParameterSpec[] lmsParams = ((LMSHSSKeyGenParameterSpec)params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams.length];
            for (int i = 0; i != lmsParams.length; i++)
            {
                hssParams[i] = new LMSParameters(lmsParams[i].getLMSigParameters(), lmsParams[i].getLMOtsParameters());
            }
            param = new HSSKeyGenerationParameters(hssParams, random);

            engine = new HSSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSParameterSpec)
        {
            LMSParameterSpec lmsParams = (LMSParameterSpec)params;

            param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getLMSigParameters(), lmsParams.getLMOtsParameters()), random);

            engine = new LMSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSHSSParameterSpec)
        {
            LMSParameterSpec[] lmsParams = ((LMSHSSParameterSpec)params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams.length];
            for (int i = 0; i != lmsParams.length; i++)
            {
                hssParams[i] = new LMSParameters(lmsParams[i].getLMSigParameters(), lmsParams[i].getLMOtsParameters());
            }
            param = new HSSKeyGenerationParameters(hssParams, random);

            engine = new HSSKeyPairGenerator();
            engine.init(param);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("parameter object not a LMSParameterSpec/LMSHSSParameterSpec");
        }

        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new LMSKeyGenerationParameters(new LMSParameters(LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w2), random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();

        if (engine instanceof LMSKeyPairGenerator)
        {
            LMSPublicKeyParameters pub = (LMSPublicKeyParameters)pair.getPublic();
            LMSPrivateKeyParameters priv = (LMSPrivateKeyParameters)pair.getPrivate();

            return new KeyPair(new BCLMSPublicKey(pub), new BCLMSPrivateKey(priv));
        }
        else
        {
            HSSPublicKeyParameters pub = (HSSPublicKeyParameters)pair.getPublic();
            HSSPrivateKeyParameters priv = (HSSPrivateKeyParameters)pair.getPrivate();

            return new KeyPair(new BCLMSPublicKey(pub), new BCLMSPrivateKey(priv));
        }
    }
}
