package org.bouncycastle.operator.jcajce;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.FixedLengthContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.ExtendedContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.Strings;

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

    // NOTE: LMS (org.bouncycastle.pqc.crypto.lms) is excluded from the jdk1.4 distribution
    // (ant/jdk14.xml), so the base getSigDigAlgId(PublicKey)/LMSigParameters lookup and the
    // JcaContentSignerBuilder(String, PublicKey) constructor built on it are dropped here.

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
                                    PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams(signatureAlgorithm, pssSpec));
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
                final int fixedLength = getFixedSignatureLength(signatureAlgId, privateKey);
                if (fixedLength > 0)
                {
                    return new FixedLengthContentSigner()
                    {
                        public int getSignatureLength()
                        {
                            return fixedLength;
                        }

                        public AlgorithmIdentifier getAlgorithmIdentifier()
                        {
                            return contentSigner.getAlgorithmIdentifier();
                        }

                        public OutputStream getOutputStream()
                        {
                            return contentSigner.getOutputStream();
                        }

                        public byte[] getSignature()
                        {
                            return contentSigner.getSignature();
                        }
                    };
                }

                return contentSigner;
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new OperatorCreationException("cannot create signer: " + e.getMessage(), e);
        }
    }

    /**
     * Return the fixed signature length in octets for the passed in algorithm
     * and key, or -1 when the length varies (e.g. DER-encoded ECDSA/DSA) or
     * cannot be determined. RSA (PKCS#1 v1.5 and PSS) signatures are the
     * modulus size; Ed25519/Ed448 and ML-DSA are constants.
     */
    private static int getFixedSignatureLength(AlgorithmIdentifier sigAlgId, PrivateKey privateKey)
    {
        if (privateKey instanceof RSAPrivateKey)
        {
            return (((RSAPrivateKey)privateKey).getModulus().bitLength() + 7) / 8;
        }

        ASN1ObjectIdentifier algorithm = sigAlgId.getAlgorithm();
        if (EdECObjectIdentifiers.id_Ed25519.equals(algorithm))
        {
            return 64;
        }
        if (EdECObjectIdentifiers.id_Ed448.equals(algorithm))
        {
            return 114;
        }
        if (NISTObjectIdentifiers.id_ml_dsa_44.equals(algorithm))
        {
            return 2420;
        }
        if (NISTObjectIdentifiers.id_ml_dsa_65.equals(algorithm))
        {
            return 3309;
        }
        if (NISTObjectIdentifiers.id_ml_dsa_87.equals(algorithm))
        {
            return 4627;
        }

        return -1;
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

    // NOTE: java.security.spec.PSSParameterSpec on JRE 1.4 has only getSaltLength() - no
    // getDigestAlgorithm()/getMGFParameters()/getTrailerField(), and MGF1ParameterSpec (Java 5)
    // does not exist at all - so the digest name is derived from the signature algorithm string
    // instead (e.g. "SHA256withRSAandMGF1" -> "SHA256"), used for both the main and MGF1 digest,
    // and the trailer field defaults to RSASSAPSSparams.DEFAULT_TRAILER_FIELD.
    private static RSASSAPSSparams createPSSParams(String signatureAlgorithm, PSSParameterSpec pssSpec)
    {
        DigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier digId = digFinder.find(signatureAlgorithm.substring(0, signatureAlgorithm.indexOf("w")));
        if (digId.getParameters() == null)
        {
            digId = new AlgorithmIdentifier(digId.getAlgorithm(), DERNull.INSTANCE);
        }
        AlgorithmIdentifier mgfDig = digFinder.find(signatureAlgorithm.substring(0, signatureAlgorithm.indexOf("w")));
        if (mgfDig.getParameters() == null)
        {
            mgfDig = new AlgorithmIdentifier(mgfDig.getAlgorithm(), DERNull.INSTANCE);
        }

        return new RSASSAPSSparams(
            digId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgfDig),
            ASN1Integer.valueOf(pssSpec.getSaltLength()),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    }
}
