package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
//import org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

public class AlgorithmParameterGeneratorSpi
    extends java.security.AlgorithmParameterGeneratorSpi
{
    protected SecureRandom random;
    protected int strength = 1024;

    protected void engineInit(
        int strength,
        SecureRandom random)
    {
        if (strength < 512 || strength > 1024 || strength % 64 != 0)
        {
            throw new InvalidParameterException("strength must be from 512 - 1024 and a multiple of 64");
        }

        this.strength = strength;
        this.random = random;
    }

    protected void engineInit(
        AlgorithmParameterSpec genParamSpec,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for DSA parameter generation.");
    }

    protected AlgorithmParameters engineGenerateParameters()
    {
        DSAParametersGenerator pGen = new DSAParametersGenerator();

        if (random != null)
        {
            pGen.init(strength, 20, random);
        }
        else
        {
            pGen.init(strength, 20, new SecureRandom());
        }

        DSAParameters p = pGen.generateParameters();

        AlgorithmParameters params;

        try
        {
            params = AlgorithmParameters.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
            params.init(new DSAParameterSpec(p.getP(), p.getQ(), p.getG()));
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage());
        }

        return params;
    }
}
