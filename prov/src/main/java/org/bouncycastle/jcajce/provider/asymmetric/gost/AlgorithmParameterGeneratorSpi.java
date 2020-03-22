package org.bouncycastle.jcajce.provider.asymmetric.gost;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.GOST3410ParametersGenerator;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAlgorithmParameterGeneratorSpi;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

public class AlgorithmParameterGeneratorSpi
    extends BaseAlgorithmParameterGeneratorSpi
{
    protected SecureRandom random;
    protected int strength = 1024;

    protected void engineInit(
        int strength,
        SecureRandom random)
    {
        this.strength = strength;
        this.random = random;
    }

    protected void engineInit(
        AlgorithmParameterSpec genParamSpec,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for GOST3410 parameter generation.");
    }

    protected AlgorithmParameters engineGenerateParameters()
    {
        GOST3410ParametersGenerator pGen = new GOST3410ParametersGenerator();

        if (random != null)
        {
            pGen.init(strength, 2, random);
        }
        else
        {
            pGen.init(strength, 2, CryptoServicesRegistrar.getSecureRandom());
        }

        GOST3410Parameters p = pGen.generateParameters();

        AlgorithmParameters params;

        try
        {
            params = createParametersInstance("GOST3410");
            params.init(new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(p.getP(), p.getQ(), p.getA())));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage());
        }

        return params;
    }
}
