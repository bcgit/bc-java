package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAlgorithmParameterGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

public class AlgorithmParameterGeneratorSpi
    extends BaseAlgorithmParameterGeneratorSpi
{
    protected SecureRandom random;
    protected int strength = 2048;

    private int l = 0;

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
        if (!(genParamSpec instanceof DHGenParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("DH parameter generator requires a DHGenParameterSpec for initialisation");
        }
        DHGenParameterSpec spec = (DHGenParameterSpec)genParamSpec;

        this.strength = spec.getPrimeSize();
        this.l = spec.getExponentSize();
        this.random = random;
    }

    protected AlgorithmParameters engineGenerateParameters()
    {
        DHParametersGenerator pGen = new DHParametersGenerator();

        int certainty = PrimeCertaintyCalculator.getDefaultCertainty(strength);

        pGen.init(strength, certainty, CryptoServicesRegistrar.getSecureRandom(random));

        DHParameters p = pGen.generateParameters();

        AlgorithmParameters params;

        try
        {
            params = createParametersInstance("DH");
            params.init(new DHParameterSpec(p.getP(), p.getG(), l));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage());
        }

        return params;
    }

}
