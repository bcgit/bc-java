package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.IllegalArgumentWarningException;
import org.bouncycastle.util.Properties;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * The TBSCertificate object.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] Extensions OPTIONAL
 *      }
 * </pre>
 * <p>
 * Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
 * will parse them, but you really shouldn't be creating new ones.
 */
public class TBSCertificate
    extends ASN1Object
{
    ASN1Sequence            seq;

    ASN1Integer             version;
    ASN1Integer             serialNumber;
    AlgorithmIdentifier     signature;
    X500Name                issuer;
    Time                    startDate, endDate;
    X500Name                subject;
    SubjectPublicKeyInfo    subjectPublicKeyInfo;
    ASN1BitString           issuerUniqueId;
    ASN1BitString           subjectUniqueId;
    Extensions              extensions;
    List<String>            errors;

    public static TBSCertificate getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSCertificate getInstance(
        Object  obj)
    {
        if (obj instanceof TBSCertificate)
        {
            return (TBSCertificate)obj;
        }
        else if (obj != null)
        {
            return new TBSCertificate(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private TBSCertificate(
        ASN1Sequence seq)
    {
        int         seqStart = 0;

        this.seq = seq;

        //
        // some certficates don't include a version number - we assume v1
        //
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            version = ASN1Integer.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
        }
        else
        {
            seqStart = -1;          // field 0 is missing!
            version = new ASN1Integer(0);
        }

        boolean isV1 = false;
        boolean isV2 = false;

        if (version.hasValue(0))
        {
            isV1 = true;
        }
        else if (version.hasValue(1))
        {
            isV2 = true;
        }
        else if (!version.hasValue(2))
        {
            addError(
                String.format("Certificate version number value %d not 0, 1 or 2", version.getValue()));
        }

        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(seqStart + 1));

        signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqStart + 2));
        issuer = X500Name.getInstance(seq.getObjectAt(seqStart + 3));

        //
        // before and after dates
        //
        ASN1Sequence  dates = (ASN1Sequence)seq.getObjectAt(seqStart + 4);

        startDate = Time.getInstance(dates.getObjectAt(0));
        endDate = Time.getInstance(dates.getObjectAt(1));

        subject = X500Name.getInstance(seq.getObjectAt(seqStart + 5));

        //
        // public key info.
        //
        subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(seqStart + 6));

        int extras = seq.size() - (seqStart + 6) - 1;
        if (extras != 0 && isV1)
        {
            addError("version 1 certificate contains extra data");
            extras = 0; // Ignore the extra data
        }

        while (extras > 0)
        {
            ASN1TaggedObject extra = (ASN1TaggedObject)seq.getObjectAt(seqStart + 6 + extras);

            switch (extra.getTagNo())
            {
            case 1:
                issuerUniqueId = ASN1BitString.getInstance(extra, false);
                break;
            case 2:
                subjectUniqueId = ASN1BitString.getInstance(extra, false);
                break;
            case 3:
                if (isV2)
                {
                    addError("version 2 certificate cannot contain extensions");
                    throw new IllegalArgumentWarningException(errors, this);
                }
                try {
                    extensions = Extensions.getInstance(ASN1Sequence.getInstance(extra, true));
                } catch (IllegalArgumentWarningException ex) {
                    extensions = ex.getObject(Extensions.class);
                    addErrors(ex.getMessages());
                }
                break;
            default:
                addError("Unknown tag encountered in structure: " + extra.getTagNo());
                throw new IllegalArgumentWarningException(errors, this);
            }
            extras--;
        }

        if (errors != null) {
            throw new IllegalArgumentWarningException(errors, this);
        }
    }

    private void addError(String error) {
        if (errors == null) {
            errors = new ArrayList<>();
        }
        errors.add(error);
    }

    private void addErrors(List<String> errors) {
        for (String error : errors) {
            addError(error);
        }
    }

    public Collection<String> getErrors() {
        return errors;
    }

    public int getVersionNumber()
    {
        return version.intValueExact() + 1;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public AlgorithmIdentifier getSignature()
    {
        return signature;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public Time getStartDate()
    {
        return startDate;
    }

    public Time getEndDate()
    {
        return endDate;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPublicKeyInfo;
    }

    public ASN1BitString getIssuerUniqueId()
    {
        return issuerUniqueId;
    }

    public ASN1BitString getSubjectUniqueId()
    {
        return subjectUniqueId;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        if (Properties.getPropertyValue("org.bouncycastle.x509.allow_non-der_tbscert") != null)
        {
            if (Properties.isOverrideSet("org.bouncycastle.x509.allow_non-der_tbscert"))
            {
                return seq;
            }
        }
        else
        {
            return seq;
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        // DEFAULT Zero
        if (!version.hasValue(0))
        {
            v.add(new DERTaggedObject(true, 0, version));
        }

        v.add(serialNumber);
        v.add(signature);
        v.add(issuer);

        //
        // before and after dates
        //
        {
            ASN1EncodableVector validity = new ASN1EncodableVector(2);
            validity.add(startDate);
            validity.add(endDate);

            v.add(new DERSequence(validity));
        }

        if (subject != null)
        {
            v.add(subject);
        }
        else
        {
            v.add(new DERSequence());
        }

        v.add(subjectPublicKeyInfo);

        // Note: implicit tag
        if (issuerUniqueId != null)
        {
            v.add(new DERTaggedObject(false, 1, issuerUniqueId));
        }

        // Note: implicit tag
        if (subjectUniqueId != null)
        {
            v.add(new DERTaggedObject(false, 2, subjectUniqueId));
        }

        if (extensions != null)
        {
            v.add(new DERTaggedObject(true, 3, extensions));
        }

        return new DERSequence(v);
    }
}
