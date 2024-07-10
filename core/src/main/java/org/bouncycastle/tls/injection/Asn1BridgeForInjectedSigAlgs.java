package org.bouncycastle.tls.injection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.IOException;
import java.lang.reflect.Method;

/**
 * Represents signature algorithms injected into TLS Injection Mechanism in the BC "tls" package.
 * However, there is no compile-time dependency on "tls" from our ("core") package.
 * <p>
 * Asn1BridgeForInjectedSigAlgs tries to contact the TLS Injection Mechanism's InjectionPoint class dynamically
 * to obtain the corresponding Asn1Bridge implementation representing all the injected signature algorithms.
 * If InjectionPoint is not available, the default Asn1Bridge implementation
 * (which doesn't support any of the signature algorithms) is used.
 * The default Asn1Bridge implementation can be replaced via the replaceWith() call.
 */
public class Asn1BridgeForInjectedSigAlgs
        implements Asn1Bridge
{

    // Bill Pugh Singleton Implementation, see https://www.geeksforgeeks.org/java-singleton-design-pattern-practices-examples/
    private static class BillPughSingleton
    {
        private static Asn1Bridge INSTANCE = new Asn1BridgeForInjectedSigAlgs();
        // ^^^ not final, since we allow to replace the instance via replaceWith
    }


    private Asn1Bridge delegate = null;

    // private = do not allow to call the constructor directly; force using theInstance()
    private Asn1BridgeForInjectedSigAlgs()
    {
        // Here we try to reach the InjectionPoint class in the dependent "tls" package. If it is present,
        // we use that class as an implementation for Asn1Bridge.
        try
        {
            Class<?> c = Class.forName("org.bouncycastle.tls.injection.InjectionPoint");
            Method m1 = c.getMethod("theInstance");
            Object o = m1.invoke(c);

            Method m2 = c.getMethod("asn1Bridge");
            Object bridge = m2.invoke(o);
            assert bridge instanceof Asn1Bridge;
            this.delegate = (Asn1Bridge) bridge;
        } catch (Exception e)
        {
            // keeping the default implementation
        }
    }

    public synchronized static Asn1Bridge theInstance()
    {
        return Asn1BridgeForInjectedSigAlgs.BillPughSingleton.INSTANCE;
    }

    public synchronized static void replaceWith(Asn1Bridge newInstance)
    {
        Asn1BridgeForInjectedSigAlgs.BillPughSingleton.INSTANCE = newInstance;
    }

    @Override
    public boolean isSupportedAlgorithm(ASN1ObjectIdentifier oid)
    {
        if (delegate != null)
        {
            return delegate.isSupportedAlgorithm(oid);
        }
        else
        {
            return false;
        }
    }


    @Override
    public boolean isSupportedParameter(AsymmetricKeyParameter bcKey)
    {
        if (delegate != null)
        {
            return delegate.isSupportedParameter(bcKey);
        }
        else
        {
            return false;
        }
    }

    @Override
    public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo asnPrivateKey) throws IOException
    {
        if (delegate != null)
        {
            return delegate.createPrivateKeyParameter(asnPrivateKey);
        }
        else
        {
            throw new IOException("No injected signature algorithms to choose from.");
        }
    }

    @Override
    public PrivateKeyInfo createPrivateKeyInfo(
            AsymmetricKeyParameter bcPrivateKey,
            ASN1Set attributes) throws IOException
    {
        if (delegate != null)
        {
            return delegate.createPrivateKeyInfo(bcPrivateKey, attributes);
        }
        else
        {
            throw new IOException("No injected signature algorithms to choose from.");
        }
    }

    @Override
    public AsymmetricKeyParameter createPublicKeyParameter(
            SubjectPublicKeyInfo ansPublicKey,
            Object defaultParams) throws IOException
    {
        if (delegate != null)
        {
            return delegate.createPublicKeyParameter(ansPublicKey, defaultParams);
        }
        else
        {
            throw new IOException("No injected signature algorithms to choose from.");
        }
    }

    @Override
    public SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter bcPublicKey) throws IOException
    {
        if (delegate != null)
        {
            return delegate.createSubjectPublicKeyInfo(bcPublicKey);
        }
        else
        {
            throw new IOException("No injected signature algorithms to choose from.");
        }
    }
}
