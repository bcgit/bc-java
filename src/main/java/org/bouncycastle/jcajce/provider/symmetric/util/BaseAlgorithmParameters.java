package org.bouncycastle.jcajce.provider.symmetric.util;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.util.Arrays;

public abstract class BaseAlgorithmParameters
    extends AlgorithmParametersSpi
{
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

    protected abstract AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException;
}
