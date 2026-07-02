package org.bouncycastle.jcajce.provider.digest;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.nist.KMACwithSHAKE128_params;
import org.bouncycastle.asn1.nist.KMACwithSHAKE256_params;
import org.bouncycastle.jcajce.spec.KMACParameterSpec;
import org.bouncycastle.util.Exceptions;

/**
 * AlgorithmParameters SPI for the RFC 8702 &sect;3.4 {@code KMACwithSHAKEnnn-params}
 * SEQUENCE. Decodes ASN.1 parameters into a {@link KMACParameterSpec} and re-encodes
 * a spec back to the wire form, omitting the kMACOutputLength and customizationString
 * fields when they take their RFC 8702 defaults.
 */
abstract class KMACAlgorithmParameters
    extends AlgorithmParametersSpi
{
    private KMACParameterSpec currentSpec;

    protected abstract byte[] encodeSpec(KMACParameterSpec spec)
        throws IOException;

    protected abstract KMACParameterSpec decodeSpec(byte[] encoded);

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (!(paramSpec instanceof KMACParameterSpec))
        {
            throw new InvalidParameterSpecException(
                "KMACParameterSpec required to initialize a KMAC algorithm parameters object");
        }

        this.currentSpec = (KMACParameterSpec)paramSpec;
    }

    protected void engineInit(byte[] params)
        throws IOException
    {
        try
        {
            currentSpec = decodeSpec(params);
        }
        catch (RuntimeException e)
        {
            // A malformed encoding can surface as IllegalArgumentException (bad SEQUENCE /
            // wrong element type), ArithmeticException (ASN1Integer.intValueExact on an
            // out-of-int-range kMACOutputLength) or other RuntimeExceptions from the ASN.1
            // layer - none may escape this throws IOException decode contract.
            throw Exceptions.ioException("Not a valid KMAC Parameter encoding.", e);
        }
    }

    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        if (isASN1FormatString(format))
        {
            engineInit(params);
            return;
        }
        throw new IOException("Unknown parameter format " + format);
    }

    protected byte[] engineGetEncoded()
        throws IOException
    {
        if (currentSpec == null)
        {
            throw new IOException("no parameter spec available");
        }
        return encodeSpec(currentSpec);
    }

    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        if (isASN1FormatString(format))
        {
            return engineGetEncoded();
        }
        return null;
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }
        if (paramSpec == KMACParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
        {
            return currentSpec;
        }
        throw new InvalidParameterSpecException("unknown parameter spec passed to KMAC parameters object");
    }

    protected String engineToString()
    {
        return "KMAC Parameters";
    }

    private static boolean isASN1FormatString(String format)
    {
        return format == null || format.equals("ASN.1") || format.equalsIgnoreCase("X.509");
    }

    public static class KMac128
        extends KMACAlgorithmParameters
    {
        protected byte[] encodeSpec(KMACParameterSpec spec)
            throws IOException
        {
            return new KMACwithSHAKE128_params(spec.getMacSizeInBits(), spec.getCustomizationString())
                .getEncoded(ASN1Encoding.DER);
        }

        protected KMACParameterSpec decodeSpec(byte[] encoded)
        {
            KMACwithSHAKE128_params params = KMACwithSHAKE128_params.getInstance(encoded);
            return new KMACParameterSpec(params.getOutputLength(), params.getCustomizationString());
        }
    }

    public static class KMac256
        extends KMACAlgorithmParameters
    {
        protected byte[] encodeSpec(KMACParameterSpec spec)
            throws IOException
        {
            return new KMACwithSHAKE256_params(spec.getMacSizeInBits(), spec.getCustomizationString())
                .getEncoded(ASN1Encoding.DER);
        }

        protected KMACParameterSpec decodeSpec(byte[] encoded)
        {
            KMACwithSHAKE256_params params = KMACwithSHAKE256_params.getInstance(encoded);
            return new KMACParameterSpec(params.getOutputLength(), params.getCustomizationString());
        }
    }
}
