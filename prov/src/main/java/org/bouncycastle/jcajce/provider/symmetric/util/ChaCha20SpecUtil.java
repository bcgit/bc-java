package org.bouncycastle.jcajce.provider.symmetric.util;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jcajce.spec.BCChaCha20ParameterSpec;

/**
 * Converts the JDK's {@code javax.crypto.spec.ChaCha20ParameterSpec} (Java 11 and later) into the BC equivalent,
 * {@link BCChaCha20ParameterSpec}, so the provider only has to handle the BC type.
 * <p>
 * This copy works by reflection, so it compiles for any Java version and finds the JDK class wherever the
 * runtime has it - including from the legacy distributions, which carry no multi-release overlays. The jdk1.11
 * copy uses the class directly. The two copies must keep the same public members: a caller compiled against this
 * one is paired at runtime with whichever copy the JVM loads.
 * </p>
 */
public class ChaCha20SpecUtil
{
    private static final Class chaCha20SpecClass;
    private static final Method nonce;
    private static final Method counter;

    static
    {
        chaCha20SpecClass = ClassUtil.loadClass(ChaCha20SpecUtil.class, "javax.crypto.spec.ChaCha20ParameterSpec");

        if (chaCha20SpecClass != null)
        {
            nonce = extractMethod("getNonce");
            counter = extractMethod("getCounter");
        }
        else
        {
            nonce = null;
            counter = null;
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
                    return chaCha20SpecClass.getDeclaredMethod(name, new Class[0]);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            return null;
        }
    }

    /**
     * Convert a {@code javax.crypto.spec.ChaCha20ParameterSpec} into the BC equivalent.
     *
     * @param paramSpec the parameter spec to convert, may be null.
     * @return the equivalent {@link BCChaCha20ParameterSpec}, or null if paramSpec is not a
     * {@code javax.crypto.spec.ChaCha20ParameterSpec}.
     * @throws InvalidAlgorithmParameterException if paramSpec is one, but its values cannot be read.
     */
    public static BCChaCha20ParameterSpec toBCChaCha20Spec(final AlgorithmParameterSpec paramSpec)
        throws InvalidAlgorithmParameterException
    {
        if (chaCha20SpecClass == null || !chaCha20SpecClass.isInstance(paramSpec))
        {
            return null;
        }

        try
        {
            return (BCChaCha20ParameterSpec)AccessController.doPrivileged(new PrivilegedExceptionAction()
            {
                public Object run()
                    throws Exception
                {
                    return new BCChaCha20ParameterSpec((byte[])nonce.invoke(paramSpec, new Object[0]),
                        ((Integer)counter.invoke(paramSpec, new Object[0])).intValue());
                }
            });
        }
        catch (Exception e)
        {
            throw new InvalidAlgorithmParameterException("Cannot process ChaCha20ParameterSpec.");
        }
    }
}
