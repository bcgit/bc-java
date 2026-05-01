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
import java.security.spec.MGF1ParameterSpec;
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
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.TeeOutputStream;

/**
 * General builder class for ContentSigner operators based on the JCA.
 */
public class JcaContentSignerBuilder
{
    private static final Set isAlgIdFromPrivate = new HashSet();
    private static final DefaultSignatureAlgorithmIdentifierFinder SIGNATURE_ALGORITHM_IDENTIFIER_FINDER = new DefaultSignatureAlgorithmIdentifierFinder();

    static
    {
        isAlgIdFromPrivate.add("COMPOSITE");
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

    //
    // at the moment LMS is the only algorithm like this, we can wing it with other public keys.
    //
    private static AlgorithmIdentifier getSigDigAlgId(PublicKey publicKey)
    {
        byte[] encoded = publicKey.getEncoded();
        SubjectPublicKeyInfo subInfo = SubjectPublicKeyInfo.getInstance(encoded);

        if (subInfo.getAlgorithm().getAlgorithm().equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig))
        {
            byte[] keyData = subInfo.getPublicKeyData().getOctets();

            int type = Pack.bigEndianToInt(keyData, 4);
            LMSigParameters sigParams = LMSigParameters.getParametersForType(type);

            return new AlgorithmIdentifier(sigParams.getDigestOID());
        }

        return null;
    }

    /**
     * Constructor which calculates the digest algorithm used from the public key, if necessary.
     * <p>
     * Some PKIX operations, such as CMS signing, require the digest algorithm used for in the
     * signature. Some algorithms, such as LMS, use different digests with different parameter sets but the same OID
     * is used to represent the signature. In this case we either need to be told what digest is associated
     * with the parameter set, or we need the public key so we can work it out.
     * </p>
     *
     * @param signatureAlgorithm the signature algorithm we perform.
     * @param verificationKey the public key associated with our private key.
     */
    public JcaContentSignerBuilder(String signatureAlgorithm, PublicKey verificationKey)
    {
        this(signatureAlgorithm, getSigDigAlgId(verificationKey));
    }

    /**
     * Constructor which includes the digest algorithm identifier used.
     * <p>
     * Some PKIX operations, such as CMS signing, require the digest algorithm used for in the
     * signature, this constructor allows the digest algorithm identifier to
     * be explicitly specified.
     * </p>
     *
     * @param signatureAlgorithm the signature algorithm we perform.
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
                                    PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams(pssSpec));
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
        //Use this legacy method only for composite private keys (they have that identifier)
        if (privateKey instanceof CompositePrivateKey && ((CompositePrivateKey)privateKey).getAlgorithmIdentifier().getAlgorithm().equals(MiscObjectIdentifiers.id_composite_key))
        {
            return buildComposite((CompositePrivateKey)privateKey);
        }
        
        try
        {
            if (sigAlgSpec == null)
            {
                this.sigAlgId = getSigAlgId(privateKey);
            }

            final AlgorithmIdentifier signatureAlgId = sigAlgId;
            final Signature sig = helper.createSignature(sigAlgId);

            if (random != null)
            {
                sig.initSign(privateKey, random);
            }
            else
            {
                sig.initSign(privateKey);
            }

            final ContentSigner contentSigner = new ContentSigner()
            {
                private OutputStream stream = OutputStreamFactory.createStream(sig);

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
                        return sig.sign();
                    }
                    catch (SignatureException e)
                    {
                        throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                    }
                }
            };

            if (signatureDigestAlgorithm != null)
            {
                return new ExtendedContentSigner()
                {
                    private final AlgorithmIdentifier digestAlgorithm = signatureDigestAlgorithm;
                    private final ContentSigner signer = contentSigner;

                    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
                    {
                        return digestAlgorithm;
                    }

                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return signer.getAlgorithmIdentifier();
                    }

                    public OutputStream getOutputStream()
                    {
                        return signer.getOutputStream();
                    }

                    public byte[] getSignature()
                    {
                        return signer.getSignature();
                    }
                };
            }
            else
            {
                return contentSigner;
            }
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

    private ContentSigner buildComposite(CompositePrivateKey privateKey)
        throws OperatorCreationException
    {
        try
        {
            List<PrivateKey> privateKeys = privateKey.getPrivateKeys();
            final ASN1Sequence sigAlgIds = ASN1Sequence.getInstance(sigAlgId.getParameters());
            final Signature[] sigs = new Signature[sigAlgIds.size()];

            for (int i = 0; i != sigAlgIds.size(); i++)
            {
                sigs[i] = helper.createSignature(AlgorithmIdentifier.getInstance(sigAlgIds.getObjectAt(i)));

                if (random != null)
                {
                    sigs[i].initSign(privateKeys.get(i), random);
                }
                else
                {
                    sigs[i].initSign(privateKeys.get(i));
                }
            }

            OutputStream sStream = OutputStreamFactory.createStream(sigs[0]);
            for (int i = 1; i != sigs.length; i++)
            {
                sStream = new TeeOutputStream(sStream, OutputStreamFactory.createStream(sigs[i]));
            }

            final OutputStream sigStream = sStream;

            return new ContentSigner()
            {
                OutputStream stream = sigStream;

                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return sigAlgId;
                }

                public OutputStream getOutputStream()
                {
                    return stream;
                }

                public byte[] getSignature()
                {
                    try
                    {
                        ASN1EncodableVector sigV = new ASN1EncodableVector();

                        for (int i = 0; i != sigs.length; i++)
                        {
                            sigV.add(new DERBitString(sigs[i].sign()));
                        }

                        return new DERSequence(sigV).getEncoded(ASN1Encoding.DER);
                    }
                    catch (IOException e)
                    {
                        throw new RuntimeOperatorException("exception encoding signature: " + e.getMessage(), e);
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

    private static RSASSAPSSparams createPSSParams(PSSParameterSpec pssSpec)
    {
        DigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier digId = digFinder.find(pssSpec.getDigestAlgorithm());
        if (digId.getParameters() == null)
        {
            digId = new AlgorithmIdentifier(digId.getAlgorithm(), DERNull.INSTANCE);
        }
        AlgorithmIdentifier mgfDig = digFinder.find(((MGF1ParameterSpec)pssSpec.getMGFParameters()).getDigestAlgorithm());
        if (mgfDig.getParameters() == null)
        {
            mgfDig = new AlgorithmIdentifier(mgfDig.getAlgorithm(), DERNull.INSTANCE);
        }

        return new RSASSAPSSparams(
            digId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgfDig),
            ASN1Integer.valueOf(pssSpec.getSaltLength()),
            ASN1Integer.valueOf(pssSpec.getTrailerField()));
    }

    private static ASN1Sequence createCompParams(CompositeAlgorithmSpec compSpec)
    {
        SignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        ASN1EncodableVector v = new ASN1EncodableVector();

        List<String> algorithmNames = compSpec.getAlgorithmNames();
        List<AlgorithmParameterSpec> algorithmSpecs = compSpec.getParameterSpecs();

        for (int i = 0; i != algorithmNames.size(); i++)
        {
            AlgorithmParameterSpec sigSpec = algorithmSpecs.get(i);
            if (sigSpec == null)
            {
                v.add(algFinder.find(algorithmNames.get(i)));
            }
            else if (sigSpec instanceof PSSParameterSpec)
            {
                v.add(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams((PSSParameterSpec)sigSpec)));
            }
            else
            {
                throw new IllegalArgumentException("unrecognized parameterSpec");
            }
        }

        return new DERSequence(v);
    }
}
