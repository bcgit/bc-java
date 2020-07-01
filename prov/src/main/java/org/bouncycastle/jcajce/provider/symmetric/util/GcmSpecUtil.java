package org.bouncycastle.jcajce.provider.symmetric.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;

public class GcmSpecUtil
{
    static final Class gcmSpecClass = ClassUtil.loadClass(GcmSpecUtil.class, "javax.crypto.spec.GCMParameterSpec");

    static final Method tLen;
    static final Method iv;

    static
    {
        if (gcmSpecClass != null)
        {
            tLen = extractMethod("getTLen");
            iv = extractMethod("getIV");
        }
        else
        {
            tLen = null;
            iv = null;
        }
    }

    private static Method extractMethod(final String name)
    {
        try
        {
            return (Method)AccessController.doPrivileged(new PrivilegedExceptionAction()
            {
                public Object run()
                    throws Exception
                {
                    return gcmSpecClass.getDeclaredMethod(name, new Class[0]);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            return null;
        }
    }

    public static boolean gcmSpecExists()
    {
        return gcmSpecClass != null;
    }

    public static boolean isGcmSpec(AlgorithmParameterSpec paramSpec)
    {
        return gcmSpecClass != null && gcmSpecClass.isInstance(paramSpec);
    }

    public static boolean isGcmSpec(Class paramSpecClass)
    {
        return gcmSpecClass == paramSpecClass;
    }

    public static AlgorithmParameterSpec extractGcmSpec(ASN1Primitive spec)
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

    static AEADParameters extractAeadParameters(final KeyParameter keyParam, final AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        try
        {
            return (AEADParameters)AccessController.doPrivileged(new PrivilegedExceptionAction()
            {
                public Object run()
                    throws Exception
                {
                    return new AEADParameters(keyParam, ((Integer)tLen.invoke(params, new Object[0])).intValue(), (byte[])iv.invoke(params, new Object[0]));
                }
            });
        }
        catch (Exception e)
        {
            throw new InvalidAlgorithmParameterException("Cannot process GCMParameterSpec.");
        }
    }

    public static GCMParameters extractGcmParameters(final AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        try
        {
            return (GCMParameters)AccessController.doPrivileged(new PrivilegedExceptionAction()
            {
                public Object run()
                    throws Exception
                {
                    return new GCMParameters((byte[])iv.invoke(paramSpec, new Object[0]), ((Integer)tLen.invoke(paramSpec, new Object[0])).intValue() / 8);
                }
            });
        }
        catch (Exception e)
        {
            throw new InvalidParameterSpecException("Cannot process GCMParameterSpec");
        }
    }
}
