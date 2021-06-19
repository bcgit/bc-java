package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.Certificate;
import org.bouncycastle.oer.its.CertificateBase;
import org.bouncycastle.oer.its.CertificateType;
import org.bouncycastle.oer.its.EccP256CurvePoint;
import org.bouncycastle.oer.its.EccP384CurvePoint;
import org.bouncycastle.oer.its.EcdsaP256Signature;
import org.bouncycastle.oer.its.EcdsaP384Signature;
import org.bouncycastle.oer.its.IssuerIdentifier;
import org.bouncycastle.oer.its.PublicVerificationKey;
import org.bouncycastle.oer.its.Signature;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.oer.its.oer.IEEE1609dot2;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class ITSCertificateBuilder
{
    private final ToBeSignedCertificate tbsCertificate;
    private final DigestCalculator digestCalculator;

    // TODO: temp constructor to get signing working.
    public ITSCertificateBuilder(ToBeSignedCertificate tbsCertificate, DigestCalculator digestCalculator)
    {
        this.tbsCertificate = tbsCertificate;
        this.digestCalculator = digestCalculator;
    }

    /**
     * Generate an X509 certificate, based on the current issuer and subject
     * using the passed in signer.
     *
     * @param signer the content signer to be used to generate the signature validating the certificate.
     * @return a holder containing the resulting signed certificate.
     */
    public ITSCertificate build(
        ITSContentSigner signer)
    {
        //tbsGen.setSignature(signer.getAlgorithmIdentifier());
        OutputStream sOut = signer.getOutputStream();

        try
        {
            sOut.write(OEREncoder.toByteArray(tbsCertificate, IEEE1609dot2.tbsCertificate));

            sOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("cannot produce certificate signature");
        }

        byte[] signature = signer.getSignature();

        ASN1Sequence asn1Sig = ASN1Sequence.getInstance(signature);

        ToBeSignedCertificate signerCert = signer.getAssociatedCertificate().toASN1Structure().getCertificateBase().getToBeSignedCertificate();
        Signature sig = null;        // TODO: signature actually optional.
        switch (signerCert.getVerificationKeyIndicator().getChoice())
        {
        case PublicVerificationKey.ecdsaNistP256:
            sig = new Signature(Signature.ecdsaNistP256Signature, new EcdsaP256Signature(
                            new EccP256CurvePoint(EccP256CurvePoint.xOnly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                            new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
            break;
        case PublicVerificationKey.ecdsaBrainpoolP256r1:
            sig = new Signature(Signature.ecdsaBrainpoolP256r1Signature, new EcdsaP256Signature(
                            new EccP256CurvePoint(EccP256CurvePoint.xOnly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                            new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
            break;
        case PublicVerificationKey.ecdsaBrainpoolP384r1:
            sig = new Signature(Signature.ecdsaBrainpoolP384r1Signature, new EcdsaP384Signature(
                new EccP384CurvePoint(EccP384CurvePoint.xOnly, new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }

        CertificateBase.Builder baseBldr = new CertificateBase.Builder();

        try
        {
            OutputStream dOut = digestCalculator.getOutputStream();

            dOut.write(signer.getAssociatedCertificate().getEncoded());
            dOut.close();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to hash issuer cert: " + e.getMessage());
        }

        byte[] parentDigest = digestCalculator.getDigest();
        byte[] hashedID = Arrays.copyOfRange(parentDigest, parentDigest.length - 8, parentDigest.length);

        baseBldr.setVersion(new ASN1Integer(3));
        baseBldr.setType(CertificateType.Explicit);
        ASN1ObjectIdentifier digestAlg = digestCalculator.getAlgorithmIdentifier().getAlgorithm();
        if (digestAlg.equals(NISTObjectIdentifiers.id_sha256))
        {
            baseBldr.setIssuer(new IssuerIdentifier(IssuerIdentifier.sha256AndDigest, hashedID));
        }
        else if (digestAlg.equals(NISTObjectIdentifiers.id_sha384))
        {
            baseBldr.setIssuer(new IssuerIdentifier(IssuerIdentifier.sha384AndDigest, hashedID));
        }
        else
        {
            throw new IllegalStateException("unknown digest");
        }

        baseBldr.setToBeSignedCertificate(tbsCertificate);
        baseBldr.setSignature(OEROptional.getInstance(sig));

        Certificate.Builder bldr = new Certificate.Builder();

        bldr.setCertificateBase(baseBldr.createCertificateBase());

        return new ITSCertificate(bldr.createCertificate());
    }
}
