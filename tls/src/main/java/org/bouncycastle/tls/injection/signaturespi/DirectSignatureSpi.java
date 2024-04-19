package org.bouncycastle.tls.injection.signaturespi;


import org.bouncycastle.tls.injection.InjectionPoint;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.*;

/**
 * The DirectSignatureSpi class acts as a proxy for all injected SignatureSpi-s.
 * DirectSignatureSpi can be registered in JCA/JCE providers, since it has the no-arg constructor.
 * See, for example, the InjectedSigAlgorithms class, which registers the full class name
 * "org.bouncycastle.tls.injection.signaturespi.DirectSignatureSpi" when configuring a provider.
 *
 * Internally, DirectSignatureSpi tries all injected SignatureSpi factories until
 * some factory returns a valid SignatureSpi. Then this SignatureSpi is used as a delegate
 * to which SignatureSpi method invocations are forwarded (via Java reflection due to protected method declarations).
 *
 * #tls-injection
 *
 * @author Sergejs Kozlovics
 */
public class DirectSignatureSpi extends java.security.SignatureSpi
{


    private java.security.SignatureSpi delegate = null; // will be initialized in engineInitVerify

    public DirectSignatureSpi() // must be no-arg constructor, full class name is used within the provider
    {
    }

    private Method findDirectOrInheritedMethod(Class c, String methodName, Class... args) {
        Method m = null;
        while (c!=null) {
            for (Method mm : c.getDeclaredMethods()) {
                // this is an optimization: we don't check all arg types, just their number
                // (for SignatureSpi-s that's sufficient)
                if (mm.getName().equals(methodName) && (args.length == mm.getParameterTypes().length))
                    m = mm;
            }
            if (m!=null)
                break;
            c = c.getSuperclass();
        }
        return m;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
    {

        delegate = InjectionPoint.sigAlgs().signatureSpiFor(publicKey);

        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineInitVerify", PublicKey.class);
        if (m==null)
            throw new RuntimeException("Method engineInitVerify not found");

        try {
            m.setAccessible(true);
            m.invoke(delegate, publicKey);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        delegate = InjectionPoint.sigAlgs().signatureSpiFor(privateKey);

        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineInitSign", PrivateKey.class);
        if (m==null)
            throw new RuntimeException("Method engineInitSign not found");

        try {
            m.setAccessible(true);
            m.invoke(delegate, privateKey);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineUpdate", Byte.TYPE);
        if (m==null)
            throw new RuntimeException("Method engineUpdate(1) not found");

        try {
            m.setAccessible(true);
            m.invoke(delegate, b);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineUpdate", Array.class, Integer.TYPE, Integer.TYPE);
        if (m==null)
            throw new RuntimeException("Method engineUpdate(3) not found");
        try {
            m.setAccessible(true);
            m.invoke(delegate, b, off, len);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineSign");
        if (m==null)
            throw new RuntimeException("Method engineSign not found");

        try {
            m.setAccessible(true);
            return (byte[])m.invoke(delegate);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineVerify", Array.class);
        if (m==null)
            throw new RuntimeException("Method engineVerify not found");

        try {
            m.setAccessible(true);
            return (boolean) m.invoke(delegate, sigBytes);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineSetParameter", String.class, Object.class);
        if (m==null)
            throw new RuntimeException("Method engineSetParameter not found");

        try {
            m.setAccessible(true);
            m.invoke(delegate, param, value);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        Class c = delegate.getClass(); // searching for the method in the class or in base classes
        Method m = findDirectOrInheritedMethod(c, "engineGetParameter", String.class);
        if (m==null)
            throw new RuntimeException("Method engineGetParameter not found");

        try {
            m.setAccessible(true);
            return m.invoke(delegate, param);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

}
