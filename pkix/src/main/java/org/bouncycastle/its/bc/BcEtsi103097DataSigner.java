package org.bouncycastle.its.bc;

import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.io.SignerOutputStream;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ETSIDataSigner;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;

public class BcEtsi103097DataSigner
    implements ETSIDataSigner
{
    private final ECPrivateKeyParameters privKey;
    private final ASN1ObjectIdentifier curveID;
    private final AlgorithmIdentifier digestAlgo;
    private final ExtendedDigest digest;

    private DSADigestSigner signer;

    public BcEtsi103097DataSigner(ECPrivateKeyParameters privKey)
    {
        this.privKey = privKey;
        this.curveID = ((ECNamedDomainParameters)privKey.getParameters()).getName();
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

        try
        {
            this.digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("cannot recognise digest type: " + digestAlgo.getAlgorithm());
        }
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    public OutputStream getOutputStream()
    {
        signer = new DSADigestSigner(new ECDSASigner(), digest);
        signer.init(true, privKey);

        return new SignerOutputStream(signer);
    }

    public Signature getSignature()
    {
        byte[] sig = signer.generateSignature();

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return ECDSAEncoder.toITS(SECObjectIdentifiers.secp256r1, sig);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return ECDSAEncoder.toITS(TeleTrusTObjectIdentifiers.brainpoolP256r1, sig);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return ECDSAEncoder.toITS(NISTObjectIdentifiers.id_sha384, sig);
        }
        throw new IllegalStateException("unrecognised curve " + curveID);
    }
}
