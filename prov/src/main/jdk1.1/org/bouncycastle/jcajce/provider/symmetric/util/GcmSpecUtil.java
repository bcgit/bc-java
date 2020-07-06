package org.bouncycastle.jcajce.provider.symmetric.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;

public class GcmSpecUtil
{
    private static Method extractMethod(final String name)
    {
	return null;
    }

    public static boolean gcmSpecExists()
    {
        return false;
    }

    public static boolean isGcmSpec(AlgorithmParameterSpec paramSpec)
    {
        return false;
    }

    public static boolean isGcmSpec(Class paramSpecClass)
    {
        return false;
    }

    public static AlgorithmParameterSpec extractGcmSpec(ASN1Primitive spec)
    {
	return null;
    }

    static AEADParameters extractAeadParameters(final KeyParameter keyParam, final AlgorithmParameterSpec params)
    {
	return null;
    }

    public static GCMParameters extractGcmParameters(final AlgorithmParameterSpec paramSpec)
    {
	return null;
    }
}
