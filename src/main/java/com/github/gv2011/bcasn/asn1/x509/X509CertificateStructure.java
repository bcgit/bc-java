package com.github.gv2011.bcasn.asn1.x509;

import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DERBitString;
import com.github.gv2011.bcasn.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.x500.X500Name;

/**
 * an X509Certificate structure.
 * <pre>
 *  Certificate ::= SEQUENCE {
 *      tbsCertificate          TBSCertificate,
 *      signatureAlgorithm      AlgorithmIdentifier,
 *      signature               BIT STRING
 *  }
 * </pre>
 * @deprecated use org.bouncycastle.asn1.x509.Certificate
 */
public class X509CertificateStructure
    extends ASN1Object
    implements X509ObjectIdentifiers, PKCSObjectIdentifiers
{
    ASN1Sequence  seq;
    TBSCertificateStructure tbsCert;
    AlgorithmIdentifier     sigAlgId;
    DERBitString            sig;

    public static X509CertificateStructure getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static X509CertificateStructure getInstance(
        Object  obj)
    {
        if (obj instanceof X509CertificateStructure)
        {
            return (X509CertificateStructure)obj;
        }
        else if (obj != null)
        {
            return new X509CertificateStructure(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public X509CertificateStructure(
        ASN1Sequence  seq)
    {
        this.seq = seq;

        //
        // correct x509 certficate
        //
        if (seq.size() == 3)
        {
            tbsCert = TBSCertificateStructure.getInstance(seq.getObjectAt(0));
            sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

            sig = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for a certificate");
        }
    }

    public TBSCertificateStructure getTBSCertificate()
    {
        return tbsCert;
    }

    public int getVersion()
    {
        return tbsCert.getVersion();
    }

    public ASN1Integer getSerialNumber()
    {
        return tbsCert.getSerialNumber();
    }

    public X500Name getIssuer()
    {
        return tbsCert.getIssuer();
    }

    public Time getStartDate()
    {
        return tbsCert.getStartDate();
    }

    public Time getEndDate()
    {
        return tbsCert.getEndDate();
    }

    public X500Name getSubject()
    {
        return tbsCert.getSubject();
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return tbsCert.getSubjectPublicKeyInfo();
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return sigAlgId;
    }

    public DERBitString getSignature()
    {
        return sig;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
