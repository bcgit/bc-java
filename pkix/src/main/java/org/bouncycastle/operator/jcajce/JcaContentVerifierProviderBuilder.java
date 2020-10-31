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

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.io.TeeOutputStream;

public class JcaContentVerifierProviderBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcaContentVerifierProviderBuilder()
    {
    }

    public JcaContentVerifierProviderBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaContentVerifierProviderBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

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
                if (algorithm.getAlgorithm().equals(MiscObjectIdentifiers.id_alg_composite))
                {
                    return createCompositeVerifier(algorithm, certificate.getPublicKey());
                }
                else
                {
                    Signature sig;
                    try
                    {
                        sig = helper.createSignature(algorithm);

                        sig.initVerify(certificate.getPublicKey());
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
                if (algorithm.getAlgorithm().equals(MiscObjectIdentifiers.id_alg_composite))
                {
                    return createCompositeVerifier(algorithm, publicKey);
                }

                if (publicKey instanceof CompositePublicKey)
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

    private ContentVerifier createCompositeVerifier(AlgorithmIdentifier compAlgId, PublicKey publicKey)
        throws OperatorCreationException
    {
        if (publicKey instanceof CompositePublicKey)
        {
            List<PublicKey> pubKeys = ((CompositePublicKey)publicKey).getPublicKeys();
            ASN1Sequence keySeq = ASN1Sequence.getInstance(compAlgId.getParameters());
            Signature[] sigs = new Signature[keySeq.size()];
            for (int i = 0; i != keySeq.size(); i++)
            {
                AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                if (pubKeys.get(i) != null)
                {
                    sigs[i] = createSignature(sigAlg, (PublicKey)pubKeys.get(i));
                }
                else
                {
                    sigs[i] = null;
                }
            }

            return new CompositeVerifier(sigs);
        }
        else
        {
            ASN1Sequence keySeq = ASN1Sequence.getInstance(compAlgId.getParameters());
            Signature[] sigs = new Signature[keySeq.size()];
            for (int i = 0; i != keySeq.size(); i++)
            {
                AlgorithmIdentifier sigAlg = AlgorithmIdentifier.getInstance(keySeq.getObjectAt(i));
                try
                {
                    sigs[i] = createSignature(sigAlg, publicKey);
                }
                catch (Exception e)
                {
                    sigs[i] = null;
                    // continue
                }
            }

            return new CompositeVerifier(sigs);
        }
    }

    private Signature createSignature(AlgorithmIdentifier algorithm, PublicKey publicKey)
        throws OperatorCreationException
    {
        try
        {
            Signature sig = helper.createSignature(algorithm);

            sig.initVerify(publicKey);

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

    private class SigVerifier
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

    private class RawSigVerifier
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

    private class CompositeVerifier
        implements ContentVerifier
    {
        private Signature[] sigs;
        private OutputStream stream;

        public CompositeVerifier(Signature[] sigs)
            throws OperatorCreationException
        {
            this.sigs = sigs;

            int start = 0;
            while (start < sigs.length && sigs[start] == null)
            {
                start++;
            }

            if (start == sigs.length)
            {
                throw new OperatorCreationException("no matching signature found in composite");
            }
            this.stream = OutputStreamFactory.createStream(sigs[start]);
            for (int i = start + 1; i != sigs.length; i++)
            {
                if (sigs[i] != null)
                {
                    this.stream = new TeeOutputStream(this.stream, OutputStreamFactory.createStream(sigs[i]));
                }
            }
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite);
        }

        public OutputStream getOutputStream()
        {
            return stream;
        }

        public boolean verify(byte[] expected)
        {
            try
            {
                ASN1Sequence sigSeq = ASN1Sequence.getInstance(expected);
                boolean failed = false;
                for (int i = 0; i != sigSeq.size(); i++)
                {
                    if (sigs[i] != null)
                    {
                        if (!sigs[i].verify(DERBitString.getInstance(sigSeq.getObjectAt(i)).getBytes()))
                        {
                            failed = true;
                        }
                    }
                }
                return !failed;
            }
            catch (SignatureException e)
            {
                throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
            }
        }
    }
}