package org.bouncycastle.its.jcajce;

import java.io.OutputStream;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.its.operator.ETSIDataVerifierProvider;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;

public class JcaETSI103097DataVerifierProvider
    implements ETSIDataVerifierProvider
{
    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JcaETSI103097DataVerifierProvider build(PublicKey publicKey)
        {
            return new JcaETSI103097DataVerifierProvider((ECPublicKey)publicKey, helper);
        }
    }

    private final ASN1ObjectIdentifier curveID;
    private final AlgorithmIdentifier digestAlgo;
    private final ECPublicKey publicKey;
    private final JcaJceHelper helper;
    private final int sigChoice;
    private final String signer;

    private JcaETSI103097DataVerifierProvider(ECPublicKey publicKey, JcaJceHelper helper)
    {
        this.publicKey = publicKey;
        this.helper = helper;

        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        curveID = ASN1ObjectIdentifier.getInstance(pkInfo.getAlgorithm().getParameters());

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            signer = "SHA256withECDSA";
            sigChoice = Signature.ecdsaNistP256Signature;
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            signer = "SHA256withECDSA";
            sigChoice = Signature.ecdsaBrainpoolP256r1Signature;
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
            signer = "SHA384withECDSA";
            sigChoice = Signature.ecdsaBrainpoolP384r1Signature;
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

    }

    public ContentVerifier getContentVerifier(int signatureChoice)
        throws OperatorCreationException
    {
        if (sigChoice != signatureChoice)
        {
            throw new OperatorCreationException("wrong verifier for algorithm: " + signatureChoice);
        }

        final java.security.Signature sigt;
        try
        {
            sigt = helper.createSignature(signer);
            sigt.initVerify(publicKey);
        }
        catch (Exception e)
        {
            throw new OperatorCreationException("cannot create signature: " + e.getMessage(), e);
        }

        return new ContentVerifier()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return null;
            }

            public OutputStream getOutputStream()
            {
                return OutputStreamFactory.createStream(sigt);
            }

            public boolean verify(byte[] expected)
            {
                try
                {
                    return sigt.verify(expected);
                }
                catch (SignatureException e)
                {
                    throw new IllegalStateException("unable to check signature: " + e.getMessage(), e);
                }
            }
        };
    }
}
