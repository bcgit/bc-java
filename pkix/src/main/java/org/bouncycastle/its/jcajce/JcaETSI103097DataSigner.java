package org.bouncycastle.its.jcajce;

import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ETSIDataSigner;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaETSI103097DataSigner
    implements ETSIDataSigner
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

        public JcaETSI103097DataSigner build(PrivateKey privateKey)
        {
            return new JcaETSI103097DataSigner((ECPrivateKey)privateKey, helper);
        }
    }

    private final ECPrivateKey privKey;
    private final ASN1ObjectIdentifier curveID;
    private final AlgorithmIdentifier digestAlgo;
    private final DigestCalculator digest;
    private final JcaJceHelper helper;
    private final String signer;

    private java.security.Signature sig;

    private JcaETSI103097DataSigner(ECPrivateKey privateKey, JcaJceHelper helper)
    {
        this.privKey = privateKey;
        this.helper = helper;

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
            sig = helper.createSignature(signer);
            sig.initSign(privKey);
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
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    public OutputStream getOutputStream()
    {
        return OutputStreamFactory.createStream(sig);
    }

    public Signature getSignature()
    {
        byte[] s;
        try
        {
            s = sig.sign();
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return ECDSAEncoder.toITS(SECObjectIdentifiers.secp256r1, s);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return ECDSAEncoder.toITS(TeleTrusTObjectIdentifiers.brainpoolP256r1, s);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return ECDSAEncoder.toITS(NISTObjectIdentifiers.id_sha384, s);
        }
        throw new IllegalStateException("unrecognised curve " + curveID);
    }
}
