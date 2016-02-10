package org.bouncycastle.pqc.jcajce.provider.sphincs;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.pqc.asn1.SPHINCS256SigParams;

public class AlgorithmParametersSpi
    extends java.security.AlgorithmParametersSpi
{
    private SPHINCS256SigParams currentSpec;

    protected boolean isASN1FormatString(String format)
    {
        return format == null || format.equals("ASN.1");
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }

        return localEngineGetParameterSpec(paramSpec);
    }

    /**
     * Return the X.509 ASN.1 structure SPHINCS256SigParams
     */
    protected byte[] engineGetEncoded()
    {
        try
        {
            return currentSpec.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error encoding SPHINCS256SigParams");
        }
    }

    protected byte[] engineGetEncoded(
        String format)
    {
        if (isASN1FormatString(format))
        {
            return engineGetEncoded();
        }

        return null;
    }

    protected AlgorithmParameterSpec localEngineGetParameterSpec(
        Class paramSpec)
        throws InvalidParameterSpecException
    {
        throw new InvalidParameterSpecException("unknown parameter spec passed to SPHINCS256 parameters object");
    }

    protected void engineInit(
        AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        throw new InvalidParameterSpecException("unknown parameter spec passed to initialise a SPHINCS256 algorithm parameters object");
    }

    protected void engineInit(
        byte[] params)
        throws IOException
    {
        try
        {
            currentSpec = SPHINCS256SigParams.getInstance(params);
        }
        catch (ClassCastException e)
        {
            throw new IOException("Not a valid SPHINCS256 Parameter encoding.");
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            throw new IOException("Not a valid SPHINCS256 Parameter encoding.");
        }
    }

    protected void engineInit(
        byte[] params,
        String format)
        throws IOException
    {
        if (isASN1FormatString(format) || format.equalsIgnoreCase("X.509"))
        {
            engineInit(params);
        }
        else
        {
            throw new IOException("Unknown parameter format " + format);
        }
    }

    protected String engineToString()
    {
        return "SPHINCS256 Parameters";
    }
}
