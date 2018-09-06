package org.bouncycastle.operator.jcajce;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;

public class JcaContentSignerBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom random;
    private String signatureAlgorithm;
    private AlgorithmIdentifier sigAlgId;
    private AlgorithmParameterSpec sigAlgSpec;

    public JcaContentSignerBuilder(String signatureAlgorithm)
    {
        this.signatureAlgorithm = signatureAlgorithm;
        this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        this.sigAlgSpec = null;
    }

    public JcaContentSignerBuilder(String signatureAlgorithm, AlgorithmParameterSpec sigParamSpec)
    {
        this.signatureAlgorithm = signatureAlgorithm;

        if (sigParamSpec instanceof PSSParameterSpec)
        {
            PSSParameterSpec pssSpec = (PSSParameterSpec)sigParamSpec;

            this.sigAlgSpec = pssSpec;
            this.sigAlgId = new AlgorithmIdentifier(
                                    PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams(pssSpec));
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
           AlgorithmIdentifier mgfDig = digFinder.find(((MGF1ParameterSpec)pssSpec.getMGFParameters()).getDigestAlgorithm());

        return new RSASSAPSSparams(
            digId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgfDig),
            new ASN1Integer(pssSpec.getSaltLength()),
            new ASN1Integer(pssSpec.getTrailerField()));
    }
}
