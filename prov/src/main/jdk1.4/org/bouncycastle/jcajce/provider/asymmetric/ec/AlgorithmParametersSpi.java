package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;

public class AlgorithmParametersSpi
    extends java.security.AlgorithmParametersSpi
{
    private ECParameterSpec ecParameterSpec;
    private String curveName;

    protected boolean isASN1FormatString(String format)
    {
        return format == null || format.equals("ASN.1");
    }

    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
        throws InvalidParameterSpecException
    {
        if (algorithmParameterSpec instanceof ECGenParameterSpec)
        {
            ECGenParameterSpec ecGenParameterSpec = (ECGenParameterSpec)algorithmParameterSpec;
            X9ECParameters params = ECNamedCurveTable.getByName(ecGenParameterSpec.getName());

            curveName = ecGenParameterSpec.getName();
            ecParameterSpec = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        }
        else if (algorithmParameterSpec instanceof ECParameterSpec)
        {
            curveName = null;
            ecParameterSpec = (ECParameterSpec)algorithmParameterSpec;
        }
        else
        {
            throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + algorithmParameterSpec.getClass().getName());
        }
    }

    protected void engineInit(byte[] bytes)
        throws IOException
    {
        engineInit(bytes, "ASN.1");
    }

   
    protected void engineInit(byte[] bytes, String format)
        throws IOException
    {
        if (isASN1FormatString(format))
        {
            X962Parameters params = X962Parameters.getInstance(bytes);

            if (params.isNamedCurve())
            {
                curveName = ECNamedCurveTable.getName(ASN1ObjectIdentifier.getInstance(params.getParameters()));
                ecParameterSpec = new ECNamedCurveParameterSpec(curveName, params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
            }

            ecParameterSpec = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH(), params.getSeed());
        }
        else
        {
            throw new IOException("Unknown encoded parameters format in AlgorithmParameters object: " + format);
        }
    }

   
    protected AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (ECParameterSpec.class.isAssignableFrom(paramSpec))
        {
            return ecParameterSpec;
        }
        else if (ECGenParameterSpec.class.isAssignableFrom(paramSpec) && curveName != null)
        {
            return new ECNamedCurveGenParameterSpec(curveName);
        }
        throw new InvalidParameterSpecException("EC AlgorithmParameters cannot convert to " + paramSpec.getName());
    }

   
    protected byte[] engineGetEncoded()
        throws IOException
    {
        return engineGetEncoded("ASN.1");
    }

   
    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (isASN1FormatString(format))
        {
            X962Parameters params;

            if (ecParameterSpec == null)     // implicitly CA
            {
                params = new X962Parameters(DERNull.INSTANCE);
            }
            else if (curveName != null)
            {
                params = new X962Parameters(ECNamedCurveTable.getOID(curveName));
            }
            else
            {
                org.bouncycastle.jce.spec.ECParameterSpec ecSpec = EC5Util.convertSpec(ecParameterSpec, false);
                X9ECParameters ecP = new X9ECParameters(
                    ecSpec.getCurve(),
                    ecSpec.getG(),
                    ecSpec.getN(),
                    ecSpec.getH(),
                    ecSpec.getSeed());

                params = new X962Parameters(ecP);
            }

            return params.getEncoded();
        }

        throw new IOException("Unknown parameters format in AlgorithmParameters object: " + format);
    }

   
    protected String engineToString()
    {
        return "EC AlgorithmParameters ";
    }
}
