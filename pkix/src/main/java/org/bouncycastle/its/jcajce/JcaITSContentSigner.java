package org.bouncycastle.its.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;

public class JcaITSContentSigner
    implements ITSContentSigner
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

        public JcaITSContentSigner build(PrivateKey privateKey)
        {
            return new JcaITSContentSigner((ECPrivateKey)privateKey, null, helper);
        }

        public JcaITSContentSigner build(PrivateKey privateKey, ITSCertificate signerCert)
        {
            return new JcaITSContentSigner((ECPrivateKey)privateKey, signerCert, helper);
        }
    }

    private final ECPrivateKey privateKey;
    private final ITSCertificate signerCert;
    private final AlgorithmIdentifier digestAlgo;
    private final DigestCalculator digest;
    private final byte[] parentData;
    private final ASN1ObjectIdentifier curveID;
    private final byte[] parentDigest;
    private final String signer;
    private final JcaJceHelper helper;

    private JcaITSContentSigner(ECPrivateKey privateKey, ITSCertificate signerCert, JcaJceHelper helper)
    {
        this.privateKey = privateKey;
        this.signerCert = signerCert;
        this.helper = helper;

        //
        // Probably the most generic way at the moment.
        //

        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        curveID = ASN1ObjectIdentifier.getInstance(pkInfo.getPrivateKeyAlgorithm().getParameters());

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            signer = "SHA256withECDSA";
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            signer = "SHA256withECDSA";
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
            signer = "SHA384withECDSA";
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

        DigestCalculatorProvider digestCalculatorProvider;

        try
        {

            JcaDigestCalculatorProviderBuilder bld = new JcaDigestCalculatorProviderBuilder().setHelper(helper);
            digestCalculatorProvider = bld.build();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex.getMessage(), ex);
        }

        try
        {
            digest = digestCalculatorProvider.get(digestAlgo);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("cannot recognise digest type: " + digestAlgo.getAlgorithm(), e);
        }

        if (signerCert != null)
        {
            try
            {
                parentData = signerCert.getEncoded();
                OutputStream os = digest.getOutputStream();
                os.write(parentData, 0, parentData.length);
                os.close();
                parentDigest = digest.getDigest();
            }
            catch (IOException e)
            {
                throw new IllegalStateException("signer certificate encoding failed: " + e.getMessage());
            }
        }
        else
        {
            // self signed so we use a null digest for the parent.
            this.parentData = null;
            this.parentDigest = digest.getDigest();
        }

    }


    public OutputStream getOutputStream()
    {
        return digest.getOutputStream();
    }


    public byte[] getSignature()
    {
        byte[] clientCertDigest = digest.getDigest();
        Signature signature;
        try
        {
            signature = helper.createSignature(signer);
            signature.initSign(privateKey);
            signature.update(clientCertDigest, 0, clientCertDigest.length);
            signature.update(parentDigest, 0, parentDigest.length);
            return signature.sign();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }


    public ITSCertificate getAssociatedCertificate()
    {
        return signerCert;
    }


    public byte[] getAssociatedCertificateDigest()
    {
        return Arrays.clone(parentDigest);
    }


    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    public ASN1ObjectIdentifier getCurveID()
    {
        return curveID;
    }

    public boolean isForSelfSigning()
    {
        return parentData == null;
    }
}
