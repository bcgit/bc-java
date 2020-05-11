package org.bouncycastle.pqc.jcajce.provider.lms;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
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
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof LMSKeyGenParameterSpec)
        {
            LMSKeyGenParameterSpec lmsParams = (LMSKeyGenParameterSpec)params;

            param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getSigParams(), lmsParams.getOtsParams()), random);

            engine = new LMSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSHSSKeyGenParameterSpec)
        {
            LMSKeyGenParameterSpec[] lmsParams = ((LMSHSSKeyGenParameterSpec)params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams.length];
            for (int i = 0; i != lmsParams.length; i++)
            {
                hssParams[i] = new LMSParameters(lmsParams[i].getSigParams(), lmsParams[i].getOtsParams());
            }
            param = new HSSKeyGenerationParameters(hssParams, random);

            engine = new HSSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSParameterSpec)
        {
            LMSParameterSpec lmsParams = (LMSParameterSpec)params;

            param = new LMSKeyGenerationParameters(new LMSParameters(lmsParams.getSigParams(), lmsParams.getOtsParams()), random);

            engine = new LMSKeyPairGenerator();
            engine.init(param);
        }
        else if (params instanceof LMSHSSParameterSpec)
        {
            LMSParameterSpec[] lmsParams = ((LMSHSSParameterSpec)params).getLMSSpecs();
            LMSParameters[] hssParams = new LMSParameters[lmsParams.length];
            for (int i = 0; i != lmsParams.length; i++)
            {
                hssParams[i] = new LMSParameters(lmsParams[i].getSigParams(), lmsParams[i].getOtsParams());
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
