package org.bouncycastle.operator.jcajce;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.operator.RuntimeOperatorException;

public class JcaContentVerifierProviderBuilder
{
    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private ContextParameterSpec context;

    public JcaContentVerifierProviderBuilder()
    {
    }

    /**
     * Set the context string the signatures were made with, for an ML-DSA, SLH-DSA or composite
     * signature made through a {@link JcaContentSignerBuilder} given a {@link ContextParameterSpec}.
     * The context is not recorded in the signature algorithm identifier, so it must be supplied
     * here; the X.509 and CMS profiles for these algorithms require the empty context, which is
     * what a builder with no context verifies against.
     *
     * @param context the context string spec, null for the empty context.
     * @return the current builder.
     */
    public JcaContentVerifierProviderBuilder setContext(ContextParameterSpec context)
    {
        this.context = context;

        return this;
    }

    public JcaContentVerifierProviderBuilder setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);

        return this;
    }

    public JcaContentVerifierProviderBuilder setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);

        return this;
    }

    public ContentVerifierProvider build(X509CertificateHolder certHolder)
        throws OperatorCreationException, CertificateException
    {
        return build(helper.convertCertificate(certHolder));
    }

    public ContentVerifierProvider build(final X509Certificate certificate)
        throws OperatorCreationException
    {
        final X509CertificateHolder certHolder;

        try
        {
            certHolder = new JcaX509CertificateHolder(certificate);
        }
        catch (CertificateEncodingException e)
        {
            throw new OperatorCreationException("cannot process certificate: " + e.getMessage(), e);
        }

        return new ContentVerifierProvider()
        {
            public boolean hasAssociatedCertificate()
            {
                return true;
            }

            public X509CertificateHolder getAssociatedCertificate()
            {
                return certHolder;
            }

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                checkNotLegacyComposite(algorithm);

                Signature sig;
                try
                {
                    sig = helper.createSignature(algorithm);

                    sig.initVerify(certificate.getPublicKey());

                    if (context != null)
                    {
                        sig.setParameter(context);
                    }
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorCreationException("exception on setup: " + e, e);
                }

                Signature rawSig = createRawSig(algorithm, certificate.getPublicKey());

                if (rawSig != null)
                {
                    return new RawSigVerifier(algorithm, sig, rawSig);
                }
                else
                {
                    return new SigVerifier(algorithm, sig);
                }
            }
        };
    }

    public ContentVerifierProvider build(final PublicKey publicKey)
        throws OperatorCreationException
    {
        return new ContentVerifierProvider()
        {
            public boolean hasAssociatedCertificate()
            {
                return false;
            }

            public X509CertificateHolder getAssociatedCertificate()
            {
                return null;
            }

            public ContentVerifier get(AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                checkNotLegacyComposite(algorithm);

                //Use this legacy method only for composite public keys (they have that identifier)
                if (publicKey instanceof CompositePublicKey
                    && ((CompositePublicKey)publicKey).getAlgorithmIdentifier().getAlgorithm().equals(MiscObjectIdentifiers.id_composite_key))
                {
                    List<PublicKey> keys = ((CompositePublicKey)publicKey).getPublicKeys();

                    for (int i = 0; i != keys.size(); i++)
                    {
                        try
                        {
                            Signature sig = createSignature(algorithm, (PublicKey)keys.get(i));

                            Signature rawSig = createRawSig(algorithm, (PublicKey)keys.get(i));

                            if (rawSig != null)
                            {
                                return new RawSigVerifier(algorithm, sig, rawSig);
                            }
                            else
                            {
                                return new SigVerifier(algorithm, sig);
                            }
                        }
                        catch (OperatorCreationException e)
                        {
                            // skip incorrect keys
                        }
                    }

                    throw new OperatorCreationException("no matching algorithm found for key");
                }
                else
                {
                    Signature sig = createSignature(algorithm, publicKey);

                    Signature rawSig = createRawSig(algorithm, publicKey);

                    if (rawSig != null)
                    {
                        return new RawSigVerifier(algorithm, sig, rawSig);
                    }
                    else
                    {
                        return new SigVerifier(algorithm, sig);
                    }
                }
            }
        };
    }

    public ContentVerifierProvider build(SubjectPublicKeyInfo publicKey)
        throws OperatorCreationException
    {
        return this.build(helper.convertPublicKey(publicKey));
    }

    private static void checkNotLegacyComposite(AlgorithmIdentifier algorithm)
        throws OperatorCreationException
    {
        if (MiscObjectIdentifiers.id_alg_composite.equals(algorithm.getAlgorithm()))
        {
            throw new OperatorCreationException("legacy composite signature algorithm not supported");
        }
    }

    private Signature createSignature(AlgorithmIdentifier algorithm, PublicKey publicKey)
        throws OperatorCreationException
    {
        try
        {
            Signature sig = helper.createSignature(algorithm);

            sig.initVerify(publicKey);

            if (context != null)
            {
                sig.setParameter(context);
            }

            return sig;
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("exception on setup: " + e, e);
        }
    }

    private Signature createRawSig(AlgorithmIdentifier algorithm, PublicKey publicKey)
    {
        Signature rawSig;
        try
        {
            rawSig = helper.createRawSignature(algorithm);

            if (rawSig != null)
            {
                rawSig.initVerify(publicKey);
            }
        }
        catch (Exception e)
        {
            rawSig = null;
        }
        return rawSig;
    }

    private static class SigVerifier
        implements ContentVerifier
    {
        private final AlgorithmIdentifier algorithm;
        private final Signature signature;

        protected final OutputStream stream;

        SigVerifier(AlgorithmIdentifier algorithm, Signature signature)
        {
            this.algorithm = algorithm;
            this.signature = signature;
            this.stream = OutputStreamFactory.createStream(signature);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithm;
        }

        public OutputStream getOutputStream()
        {
            if (stream == null)
            {
                throw new IllegalStateException("verifier not initialised");
            }

            return stream;
        }

        public boolean verify(byte[] expected)
        {
            try
            {
                return signature.verify(expected);
            }
            catch (SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
            }
        }
    }

    private static class RawSigVerifier
        extends SigVerifier
        implements RawContentVerifier
    {
        private Signature rawSignature;

        RawSigVerifier(AlgorithmIdentifier algorithm, Signature standardSig, Signature rawSignature)
        {
            super(algorithm, standardSig);
            this.rawSignature = rawSignature;
        }

        public boolean verify(byte[] expected)
        {
            try
            {
                return super.verify(expected);
            }
            finally
            {
                // we need to do this as in some PKCS11 implementations the session associated with the init of the
                // raw signature will not be freed if verify is not called on it.
                try
                {
                    rawSignature.verify(expected);
                }
                catch (Exception e)
                {
                    // ignore
                }
            }
        }

        public boolean verify(byte[] digest, byte[] expected)
        {
            try
            {
                rawSignature.update(digest);

                return rawSignature.verify(expected);
            }
            catch (SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining raw signature: " + e.getMessage(), e);
            }
            finally
            {
                // we need to do this as in some PKCS11 implementations the session associated with the init of the
                // standard signature will not be freed if verify is not called on it.
                try
                {
                    rawSignature.verify(expected);
                }
                catch (Exception e)
                {
                    // ignore
                }
            }
        }
    }
}
