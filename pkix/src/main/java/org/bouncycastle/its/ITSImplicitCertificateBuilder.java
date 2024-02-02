package org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.CertificateType;
import org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ieee1609dot2.VerificationKeyIndicator;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class ITSImplicitCertificateBuilder
    extends ITSCertificateBuilder
{
    private IssuerIdentifier issuerIdentifier;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public ITSImplicitCertificateBuilder(ITSCertificate issuer, DigestCalculatorProvider digestCalculatorProvider, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, tbsCertificate);
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public ITSCertificate build(CertificateId certificateId, BigInteger x, BigInteger y)
    {
        return build(certificateId, x, y, null);
    }

    public ITSCertificate build(CertificateId certificateId, BigInteger x, BigInteger y, PublicEncryptionKey publicEncryptionKey)
    {
        EccCurvePoint reconstructionValue;
        AlgorithmIdentifier digestAlgId;
        if (tbsCertificateBuilder.createToBeSignedCertificate().getVerifyKeyIndicator() != null)
        {
            try
            {
                EccCurvePoint eccCurvePoint = (EccCurvePoint)tbsCertificateBuilder.createToBeSignedCertificate().getVerifyKeyIndicator().getVerificationKeyIndicator();
                if (eccCurvePoint instanceof EccP256CurvePoint)
                {
                    reconstructionValue = EccP256CurvePoint.uncompressedP256(x, y);
                    digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                }
                else if (eccCurvePoint instanceof EccP384CurvePoint)
                {
                    reconstructionValue = EccP384CurvePoint.uncompressedP384(x,y);
                    digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                }
                else
                {
                    throw new IllegalStateException("unable to build as the parameter setting in VerifyKeyIndicator is not correct");
                }
            }
            catch (Exception e)
            {
                throw new IllegalStateException("unable to build as the parameter setting in VerifyKeyIndicator is not correct");
            }
        }
        else
        {
            // Default setting when there is no settings for VerifyKeyIndicator
            reconstructionValue = EccP256CurvePoint.uncompressedP256(x, y);
            digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }

        return getItsCertificate(certificateId, publicEncryptionKey, reconstructionValue, digestAlgId);
    }

    public ITSCertificate build(CertificateId certificateId, PublicEncryptionKey publicEncryptionKey)
    {
        EccCurvePoint reconstructionValue;
        AlgorithmIdentifier digestAlgId;
        if (tbsCertificateBuilder.createToBeSignedCertificate().getVerifyKeyIndicator() != null)
        {
            try
            {
                reconstructionValue = (EccCurvePoint)tbsCertificateBuilder.createToBeSignedCertificate().getVerifyKeyIndicator().getVerificationKeyIndicator();
                if (reconstructionValue instanceof EccP256CurvePoint)
                {
                    digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                }
                else if (reconstructionValue instanceof EccP384CurvePoint)
                {
                    digestAlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                }
                else
                {
                    throw new IllegalStateException("unable to build as the parameter setting in VerifyKeyIndicator is not correct");
                }
            }
            catch (Exception e)
            {
                throw new IllegalStateException("unable to build as the parameter setting in VerifyKeyIndicator is not correct");
            }
        }
        else
        {
            throw new IllegalStateException("unable to build as the parameter setting in VerifyKeyIndicator is not correct");
        }

        return getItsCertificate(certificateId, publicEncryptionKey, reconstructionValue, digestAlgId);
    }

    private ITSCertificate getItsCertificate(CertificateId certificateId, PublicEncryptionKey publicEncryptionKey, EccCurvePoint reconstructionValue, AlgorithmIdentifier digestAlgId)
    {
        ASN1ObjectIdentifier digestAlg = digestAlgId.getAlgorithm();
        DigestCalculator calculator;
        try
        {
            calculator = digestCalculatorProvider.get(digestAlgId);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException(e.getMessage(), e);
        }
        try
        {
            OutputStream os = calculator.getOutputStream();
            os.write(issuer.getEncoded());
            os.close();
        }
        catch (IOException ioex)
        {
            throw new IllegalStateException(ioex.getMessage(), ioex);
        }
        byte[] parentDigest = calculator.getDigest();
        issuerIdentifier = ITSUtil.getIssuerIdentifier(digestAlg, parentDigest);
        ToBeSignedCertificate.Builder tbsBldr = new ToBeSignedCertificate.Builder(tbsCertificateBuilder);

        tbsBldr.setId(certificateId);

        if (publicEncryptionKey != null)
        {
            tbsBldr.setEncryptionKey(publicEncryptionKey);
        }

        tbsBldr.setVerifyKeyIndicator(VerificationKeyIndicator.reconstructionValue(reconstructionValue));


        CertificateBase.Builder baseBldr = new CertificateBase.Builder();

        baseBldr.setVersion(version);
        baseBldr.setType(CertificateType.implicit);

        baseBldr.setIssuer(issuerIdentifier);

        baseBldr.setToBeSigned(tbsBldr.createToBeSignedCertificate());

        return new ITSCertificate(baseBldr.createCertificateBase());
    }
}
