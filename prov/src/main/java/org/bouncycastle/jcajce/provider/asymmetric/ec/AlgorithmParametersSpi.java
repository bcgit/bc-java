package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

public class AlgorithmParametersSpi
    extends java.security.AlgorithmParametersSpi
{
    private ECParameterSpec ecParameterSpec;
    private String curveName;

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
        throws InvalidParameterSpecException
    {
        if (algorithmParameterSpec instanceof ECGenParameterSpec)
        {
            ECGenParameterSpec ecGenParameterSpec = (ECGenParameterSpec)algorithmParameterSpec;
            X9ECParameters params = ECNamedCurveTable.getByName(ecGenParameterSpec.getName());

            curveName = ecGenParameterSpec.getName();
            ecParameterSpec = EC5Util.convertToSpec(params);
        }
    }

    @Override
    protected void engineInit(byte[] bytes)
        throws IOException
    {

    }

    @Override
    protected void engineInit(byte[] bytes, String s)
        throws IOException
    {

    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException
    {
        if (ECParameterSpec.class.isAssignableFrom(paramSpec))
        {
            return (T)ecParameterSpec;
        }
        else if (ECGenParameterSpec.class.isAssignableFrom(paramSpec) && curveName != null)
        {
            return (T)new ECGenParameterSpec(curveName);
        }
        throw new InvalidParameterSpecException("EC AlgorithmParameters cannot convert to " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded()
        throws IOException
    {
        return new byte[0];
    }

    @Override
    protected byte[] engineGetEncoded(String s)
        throws IOException
    {
        return new byte[0];
    }

    @Override
    protected String engineToString()
    {
        return null;
    }
}
