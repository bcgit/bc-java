package org.bouncycastle.operator.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.ExtendedContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorStreamException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.TeeOutputStream;

public class JcaContentSignerBuilder
{
    private static final Set isAlgIdFromPrivate = new HashSet();
    private static final DefaultSignatureAlgorithmIdentifierFinder SIGNATURE_ALGORITHM_IDENTIFIER_FINDER = new DefaultSignatureAlgorithmIdentifierFinder();

    static
    {
        isAlgIdFromPrivate.add("DILITHIUM");
        isAlgIdFromPrivate.add("SPHINCS+");
        isAlgIdFromPrivate.add("SPHINCSPlus");
        isAlgIdFromPrivate.add("ML-DSA");
        isAlgIdFromPrivate.add("SLH-DSA");
        isAlgIdFromPrivate.add("HASH-ML-DSA");
        isAlgIdFromPrivate.add("HASH-SLH-DSA");
    }

    private final String signatureAlgorithm;
    private final AlgorithmIdentifier signatureDigestAlgorithm;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;

    private AlgorithmIdentifier sigAlgId;
    private AlgorithmParameterSpec sigAlgSpec;

    /**
     * Construct a basic content signer where the signature algorithm name
     * tells us all we need to know.
     *
     * @param signatureAlgorithm the signature algorithm we perform.
     */
    public JcaContentSignerBuilder(String signatureAlgorithm)
    {
        this(signatureAlgorithm, (AlgorithmIdentifier)null);
    }

    /**
     * Constructor which includes the digest algorithm identifier used.
     * <p>
     * Some PKIX operations, such as CMS signing, require the digest algorithm used for in the
     * signature, this constructor allows the digest algorithm identifier to
     * be explicitly specified.
     * </p>
     *
     * @param signatureAlgorithm         the signature algorithm we perform.
     * @param signatureDigestAlgorithmID the public key associated with our private key.
     */
    public JcaContentSignerBuilder(String signatureAlgorithm, AlgorithmIdentifier signatureDigestAlgorithmID)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureDigestAlgorithm = signatureDigestAlgorithmID;
    }

    public JcaContentSignerBuilder(String signatureAlgorithm, AlgorithmParameterSpec sigParamSpec)
    {
        this(signatureAlgorithm, sigParamSpec, null);
    }

    public JcaContentSignerBuilder(String signatureAlgorithm, AlgorithmParameterSpec sigParamSpec, AlgorithmIdentifier signatureDigestAlgorithmID)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureDigestAlgorithm = signatureDigestAlgorithmID;

        if (sigParamSpec instanceof PSSParameterSpec)
        {
            PSSParameterSpec pssSpec = (PSSParameterSpec)sigParamSpec;

            this.sigAlgSpec = pssSpec;
            this.sigAlgId = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams(signatureAlgorithm, pssSpec));
        }
        else if (sigParamSpec instanceof CompositeAlgorithmSpec)
        {
            CompositeAlgorithmSpec compSpec = (CompositeAlgorithmSpec)sigParamSpec;

            this.sigAlgSpec = compSpec;
            this.sigAlgId = new AlgorithmIdentifier(
                MiscObjectIdentifiers.id_alg_composite, createCompParams(compSpec));
        }
        else
        {
            throw new IllegalArgumentException("unknown sigParamSpec: "
                + ((sigParamSpec == null) ? "null" : sigParamSpec.getClass().getName()));
        }
    }

    public JcaContentSignerBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcaContentSignerBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JcaContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public ContentSigner build(PrivateKey privateKey)
        throws OperatorCreationException
    {
        try
        {
            if (sigAlgSpec == null)
            {
                this.sigAlgId = getSigAlgId(privateKey);
            }

            final Signature sig = helper.createSignature(sigAlgId);
            final AlgorithmIdentifier signatureAlgId = sigAlgId;

            if (random != null)
            {
                sig.initSign(privateKey, random);
            }
            else
            {
                sig.initSign(privateKey);
            }

            return new ContentSigner()
            {
                private SignatureOutputStream stream = new SignatureOutputStream(sig);

                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return signatureAlgId;
                }

                public OutputStream getOutputStream()
                {
                    return stream;
                }

                public byte[] getSignature()
                {
                    try
                    {
                        return stream.getSignature();
                    }
                    catch (SignatureException e)
                    {
                        throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                    }
                }
            };
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create signer: " + e.getMessage(), e);
        }
    }

    private AlgorithmIdentifier getSigAlgId(PrivateKey privateKey)
    {
        if (isAlgIdFromPrivate.contains(Strings.toUpperCase(signatureAlgorithm)))
        {
            AlgorithmIdentifier sigAlgId = SIGNATURE_ALGORITHM_IDENTIFIER_FINDER.find(privateKey.getAlgorithm());
            if (sigAlgId == null)
            {
                return PrivateKeyInfo.getInstance(privateKey.getEncoded()).getPrivateKeyAlgorithm();
            }
            return sigAlgId;
        }
        else
        {
            return SIGNATURE_ALGORITHM_IDENTIFIER_FINDER.find(signatureAlgorithm);
        }
    }

    private class SignatureOutputStream
        extends OutputStream
    {
        private Signature sig;

        SignatureOutputStream(Signature sig)
        {
            this.sig = sig;
        }

        public void write(byte[] bytes, int off, int len)
            throws IOException
        {
            try
            {
                sig.update(bytes, off, len);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        public void write(byte[] bytes)
            throws IOException
        {
            try
            {
                sig.update(bytes);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        public void write(int b)
            throws IOException
        {
            try
            {
                sig.update((byte)b);
            }
            catch (SignatureException e)
            {
                throw new OperatorStreamException("exception in content signer: " + e.getMessage(), e);
            }
        }

        byte[] getSignature()
            throws SignatureException
        {
            return sig.sign();
        }
    }

    private static RSASSAPSSparams createPSSParams(String signatureAlgorithm, PSSParameterSpec pssSpec)
    {
        DigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier digId = digFinder.find(signatureAlgorithm.substring(0, signatureAlgorithm.indexOf("w")));
        AlgorithmIdentifier mgfDig = digFinder.find(signatureAlgorithm.substring(0, signatureAlgorithm.indexOf("w")));

        return new RSASSAPSSparams(
            digId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgfDig),
            new ASN1Integer(pssSpec.getSaltLength()),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    }

    private static ASN1Sequence createCompParams(CompositeAlgorithmSpec compSpec)
    {
        SignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        ASN1EncodableVector v = new ASN1EncodableVector();

        List<String> algorithmNames = compSpec.getAlgorithmNames();
        List<AlgorithmParameterSpec> algorithmSpecs = compSpec.getParameterSpecs();

        for (int i = 0; i != algorithmNames.size(); i++)
        {
            AlgorithmParameterSpec sigSpec = (AlgorithmParameterSpec)algorithmSpecs.get(i);
            if (sigSpec == null)
            {
                v.add(algFinder.find((String)algorithmNames.get(i)));
            }
            else if (sigSpec instanceof PSSParameterSpec)
            {
                v.add(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams((String)algorithmNames.get(i), (PSSParameterSpec)sigSpec)));
            }
            else
            {
                throw new IllegalArgumentException("unrecognized parameterSpec");
            }
        }

        return new DERSequence(v);
    }
}
