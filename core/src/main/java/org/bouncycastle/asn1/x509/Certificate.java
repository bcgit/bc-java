package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.IllegalArgumentWarningException;

/**
 * an X509Certificate structure.
 * <pre>
 *  Certificate ::= SEQUENCE {
 *      tbsCertificate          TBSCertificate,
 *      signatureAlgorithm      AlgorithmIdentifier,
 *      signature               BIT STRING
 *  }
 * </pre>
 */
public class Certificate
    extends ASN1Object
{
    ASN1Sequence  seq;
    TBSCertificate tbsCert;
    AlgorithmIdentifier     sigAlgId;
    ASN1BitString            sig;

    public static Certificate getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Certificate getInstance(
        Object  obj)
    {
        if (obj instanceof Certificate)
        {
            return (Certificate)obj;
        }
        else if (obj != null)
        {
            return new Certificate(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private Certificate(
        ASN1Sequence seq)
    {
        this.seq = seq;

        IllegalArgumentWarningException exception = null;

        //
        // correct x509 certficate
        //
        if (seq.size() == 3)
        {
          try {
            tbsCert = TBSCertificate.getInstance(seq.getObjectAt(0));
          } catch (IllegalArgumentWarningException ex) {
            tbsCert = (TBSCertificate) ex.getObject(TBSCertificate.class);
            exception = ex;
          }
            sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

            sig = ASN1BitString.getInstance(seq.getObjectAt(2));
        }
        else
        {
            throw new IllegalArgumentException("sequence wrong size for a certificate");
        }

        if (exception != null) {
          throw new IllegalArgumentWarningException(this, exception);
        }
    }

    public TBSCertificate getTBSCertificate()
    {
        return tbsCert;
    }

    public ASN1Integer getVersion()
    {
        return tbsCert.getVersion();
    }

    public int getVersionNumber()
    {
        return tbsCert.getVersionNumber();
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

    public ASN1BitString getSignature()
    {
        return sig;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
