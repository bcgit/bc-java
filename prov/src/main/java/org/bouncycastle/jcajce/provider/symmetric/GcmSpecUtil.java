package org.bouncycastle.jcajce.provider.symmetric;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
import org.bouncycastle.util.Integers;

class GcmSpecUtil
{
    static final Class gcmSpecClass = ClassUtil.loadClass(GcmSpecUtil.class, "javax.crypto.spec.GCMParameterSpec");

    static boolean gcmSpecExists()
    {
        return gcmSpecClass != null;
    }

    static boolean isGcmSpec(AlgorithmParameterSpec paramSpec)
    {
        return gcmSpecClass != null && gcmSpecClass.isInstance(paramSpec);
    }

    static boolean isGcmSpec(Class paramSpecClass)
    {
        return gcmSpecClass == paramSpecClass;
    }

    static AlgorithmParameterSpec extractGcmSpec(ASN1Primitive spec)
        throws InvalidParameterSpecException
    {
        try
        {
            GCMParameters gcmParams = GCMParameters.getInstance(spec);
            Constructor constructor = gcmSpecClass.getConstructor(new Class[]{Integer.TYPE, byte[].class});

            return (AlgorithmParameterSpec)constructor.newInstance(new Object[] { Integers.valueOf(gcmParams.getIcvLen() * 8), gcmParams.getNonce() });
        }
        catch (NoSuchMethodException e)
        {
            throw new InvalidParameterSpecException("No constructor found!");   // should never happen
        }
        catch (Exception e)
        {
            throw new InvalidParameterSpecException("Construction failed: " + e.getMessage());   // should never happen
        }
    }

    static GCMParameters extractGcmParameters(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        try
        {
            Method tLen = gcmSpecClass.getDeclaredMethod("getTLen", new Class[0]);
            Method iv= gcmSpecClass.getDeclaredMethod("getIV", new Class[0]);

            return new GCMParameters((byte[])iv.invoke(paramSpec, new Object[0]), ((Integer)tLen.invoke(paramSpec, new Object[0])).intValue() / 8);
        }
        catch (Exception e)
        {
            throw new InvalidParameterSpecException("Cannot process GCMParameterSpec");
        }
    }
}
