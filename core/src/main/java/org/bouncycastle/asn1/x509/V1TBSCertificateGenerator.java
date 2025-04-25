package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Generator for Version 1 TBSCertificateStructures.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      }
 * </pre>
 *
 */
public class V1TBSCertificateGenerator
{
    DERTaggedObject         version = new DERTaggedObject(true, 0, new ASN1Integer(0));

    ASN1Integer              serialNumber;
    AlgorithmIdentifier     signature;
    X500Name                issuer;
    Validity                validity;
    Time                    startDate, endDate;
    X500Name                subject;
    SubjectPublicKeyInfo    subjectPublicKeyInfo;

    public V1TBSCertificateGenerator()
    {
    }

    public void setSerialNumber(
        ASN1Integer  serialNumber)
    {
        this.serialNumber = serialNumber;
    }

    public void setSignature(
        AlgorithmIdentifier    signature)
    {
        this.signature = signature;
    }

        /**
     * @deprecated use X500Name method
     */
    public void setIssuer(
        X509Name    issuer)
    {
        this.issuer = X500Name.getInstance(issuer.toASN1Primitive());
    }

    public void setIssuer(
        X500Name issuer)
    {
        this.issuer = issuer;
    }

    public void setValidity(Validity validity)
    {
        this.validity = validity;
        this.startDate = null;
        this.endDate = null;
    }

    public void setStartDate(Time startDate)
    {
        this.validity = null;
        this.startDate = startDate;
    }

    public void setStartDate(ASN1UTCTime startDate)
    {
        setStartDate(new Time(startDate));
    }

    public void setEndDate(Time endDate)
    {
        this.validity = null;
        this.endDate = endDate;
    }

    public void setEndDate(ASN1UTCTime endDate)
    {
        setEndDate(new Time(endDate));
    }

    /**
     * @deprecated use X500Name method
     */
    public void setSubject(
        X509Name    subject)
    {
        this.subject = X500Name.getInstance(subject.toASN1Primitive());
    }

    public void setSubject(
        X500Name subject)
    {
        this.subject = subject;
    }

    public void setSubjectPublicKeyInfo(
        SubjectPublicKeyInfo    pubKeyInfo)
    {
        this.subjectPublicKeyInfo = pubKeyInfo;
    }

    public TBSCertificate generateTBSCertificate()
    {
        if ((serialNumber == null) || (signature == null) || (issuer == null) ||
            (validity == null && (startDate == null || endDate == null)) ||
            (subject == null) || (subjectPublicKeyInfo == null))
        {
            throw new IllegalStateException("not all mandatory fields set in V1 TBScertificate generator");
        }

        return new TBSCertificate(new ASN1Integer(0), serialNumber, signature, issuer,
            validity != null ? validity : new Validity(startDate, endDate), subject, subjectPublicKeyInfo, null,
            null, null);
    }
}
