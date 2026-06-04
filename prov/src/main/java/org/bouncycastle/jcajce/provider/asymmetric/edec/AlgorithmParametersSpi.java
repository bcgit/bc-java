package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

/**
 * AlgorithmParameters for the RFC 8032 EdDSA instance selectors (prehash / context) carried by
 * {@link EdDSAParameterSpec}. These parameters have <b>no encoded form</b>: RFC 8410 specifies the
 * EdDSA AlgorithmIdentifier with absent parameters, and the prehash flag / context are not part of
 * any standard ASN.1 parameter structure, so {@code engineGetEncoded} / {@code engineInit(byte[])}
 * throw {@link IOException}. The class exists as a spec container so that Signature.getParameters()
 * can report the selected instance and callers can copy it between Signature objects.
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
        if (!(paramSpec instanceof EdDSAParameterSpec))
        {
            throw new InvalidParameterSpecException("unknown AlgorithmParameterSpec for EdDSA: "
                + ((paramSpec == null) ? "null" : paramSpec.getClass().getName()));
        }

        EdDSAParameterSpec edSpec = (EdDSAParameterSpec)paramSpec;

        this.prehash = edSpec.isPrehash();
        this.context = edSpec.getContext();
        this.initialised = true;
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
