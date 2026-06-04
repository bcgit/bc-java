package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

/**
 * AlgorithmParameters for the RFC 8032 EdDSA instance selectors (prehash / context). As well as the
 * BC {@link EdDSAParameterSpec} this MR-jar overlay reads and produces the standard JDK 15+
 * {@code java.security.spec.EdDSAParameterSpec}. The parameters have <b>no encoded form</b>: RFC 8410
 * specifies the EdDSA AlgorithmIdentifier with absent parameters, so {@code engineGetEncoded} /
 * {@code engineInit(byte[])} throw {@link IOException}.
 */
public class AlgorithmParametersSpi
    extends java.security.AlgorithmParametersSpi
{
    private final String curveName;

    private boolean prehash;
    private byte[] context;
    private boolean initialised;

    AlgorithmParametersSpi(String curveName)
    {
        this.curveName = curveName;
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec instanceof java.security.spec.EdDSAParameterSpec)
        {
            java.security.spec.EdDSAParameterSpec jdkSpec = (java.security.spec.EdDSAParameterSpec)paramSpec;

            this.prehash = jdkSpec.isPrehash();
            this.context = jdkSpec.getContext().isPresent() ? jdkSpec.getContext().get() : null;
            this.initialised = true;
        }
        else if (paramSpec instanceof EdDSAParameterSpec)
        {
            EdDSAParameterSpec edSpec = (EdDSAParameterSpec)paramSpec;

            this.prehash = edSpec.isPrehash();
            this.context = edSpec.getContext();
            this.initialised = true;
        }
        else
        {
            throw new InvalidParameterSpecException("unknown AlgorithmParameterSpec for EdDSA: "
                + ((paramSpec == null) ? "null" : paramSpec.getClass().getName()));
        }
    }

    protected void engineInit(byte[] params)
        throws IOException
    {
        throw new IOException("EdDSA parameters have no encoded form (RFC 8410)");
    }

    protected void engineInit(byte[] params, String format)
        throws IOException
    {
        throw new IOException("EdDSA parameters have no encoded form (RFC 8410)");
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
        throws InvalidParameterSpecException
    {
        if (paramSpec == null)
        {
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }
        if (!initialised)
        {
            throw new InvalidParameterSpecException("parameters not initialized");
        }

        if (paramSpec == java.security.spec.EdDSAParameterSpec.class)
        {
            return (context == null)
                ? new java.security.spec.EdDSAParameterSpec(prehash)
                : new java.security.spec.EdDSAParameterSpec(prehash, context);
        }
        if (paramSpec == EdDSAParameterSpec.class || paramSpec == AlgorithmParameterSpec.class)
        {
            return new EdDSAParameterSpec(curveName, prehash, context);
        }

        throw new InvalidParameterSpecException("AlgorithmParameterSpec not recognized: " + paramSpec.getName());
    }

    protected byte[] engineGetEncoded()
        throws IOException
    {
        throw new IOException("EdDSA parameters have no encoded form (RFC 8410)");
    }

    protected byte[] engineGetEncoded(String format)
        throws IOException
    {
        throw new IOException("EdDSA parameters have no encoded form (RFC 8410)");
    }

    protected String engineToString()
    {
        return curveName + " Parameters [prehash=" + prehash
            + ", context=" + ((context == null) ? "none" : (context.length + " bytes")) + "]";
    }

    public static class Ed25519
        extends AlgorithmParametersSpi
    {
        public Ed25519()
        {
            super(EdDSAParameterSpec.Ed25519);
        }
    }

    public static class Ed448
        extends AlgorithmParametersSpi
    {
        public Ed448()
        {
            super(EdDSAParameterSpec.Ed448);
        }
    }
}
