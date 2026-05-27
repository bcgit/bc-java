package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * RFC 9763 sec. 4 {@code RequesterCertificate} CSR attribute value carrying
 * the {@code id-aa-relatedCertRequest} request.
 * <pre>
 * RequesterCertificate ::= SEQUENCE {
 *     certID        IssuerAndSerialNumber,
 *     requestTime   BinaryTime,
 *     locationInfo  UniformResourceIdentifiers,
 *     signature     BIT STRING }
 *
 * UniformResourceIdentifiers ::= SEQUENCE SIZE (1..MAX) OF URI
 * URI ::= IA5String
 * </pre>
 * The {@code signature} field carries a digital signature, computed with the
 * private key associated with the certificate identified by {@code certID},
 * over the concatenation of the DER-encoded {@code certID} and the DER-encoded
 * {@code requestTime} (RFC 9763 sec. 4.1, "<em>concatenation of DER-encoded
 * IssuerAndSerialNumber and BinaryTime</em>" — NOT a SEQUENCE wrapper). The
 * locations in {@code locationInfo} are HTTP(S) URIs or {@code data:} URIs
 * (RFC 2397) from which the CA can retrieve the related certificate.
 * <p>
 * No AlgorithmIdentifier field accompanies the signature; the verifier must
 * derive the signature algorithm from the related certificate itself (its
 * SubjectPublicKeyInfo plus any policy the CA applies).
 * <p>
 * Identified by
 * {@link PKCSObjectIdentifiers#id_aa_relatedCertRequest}
 * (OID 1.2.840.113549.1.9.16.2.60); it is the value of that PKCS#9 attribute
 * in a {@code CertificationRequestInfo}.
 */
public class RequesterCertificate
    extends ASN1Object
{
    private final IssuerAndSerialNumber certID;
    private final BinaryTime requestTime;
    private final ASN1Sequence locationInfo;
    private final ASN1BitString signature;

    public static RequesterCertificate getInstance(Object obj)
    {
        if (obj instanceof RequesterCertificate)
        {
            return (RequesterCertificate)obj;
        }
        if (obj != null)
        {
            return new RequesterCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public RequesterCertificate(
        IssuerAndSerialNumber certID,
        BinaryTime requestTime,
        String[] locationInfo,
        byte[] signature)
    {
        if (certID == null)
        {
            throw new NullPointerException("'certID' cannot be null");
        }
        if (requestTime == null)
        {
            throw new NullPointerException("'requestTime' cannot be null");
        }
        if (locationInfo == null || locationInfo.length == 0)
        {
            throw new IllegalArgumentException("'locationInfo' must contain at least one URI");
        }
        if (signature == null)
        {
            throw new NullPointerException("'signature' cannot be null");
        }

        ASN1EncodableVector uriVec = new ASN1EncodableVector(locationInfo.length);
        for (int i = 0; i < locationInfo.length; i++)
        {
            if (locationInfo[i] == null)
            {
                throw new NullPointerException("'locationInfo' entries cannot be null");
            }
            uriVec.add(new DERIA5String(locationInfo[i]));
        }

        this.certID = certID;
        this.requestTime = requestTime;
        this.locationInfo = new DERSequence(uriVec);
        this.signature = new DERBitString(signature);
    }

    private RequesterCertificate(ASN1Sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.certID = IssuerAndSerialNumber.getInstance(seq.getObjectAt(0));
        this.requestTime = BinaryTime.getInstance(seq.getObjectAt(1));
        this.locationInfo = ASN1Sequence.getInstance(seq.getObjectAt(2));
        this.signature = ASN1BitString.getInstance(seq.getObjectAt(3));

        if (locationInfo.size() < 1)
        {
            throw new IllegalArgumentException("locationInfo SEQUENCE must contain at least one URI");
        }
    }

    public IssuerAndSerialNumber getCertID()
    {
        return certID;
    }

    public BinaryTime getRequestTime()
    {
        return requestTime;
    }

    /**
     * @return the URIs from which the related certificate can be retrieved,
     *         in the encoded order. Per RFC 9763 sec. 4 these are typically
     *         HTTP/HTTPS URLs or {@code data:} URIs (RFC 2397).
     */
    public String[] getLocationInfo()
    {
        String[] uris = new String[locationInfo.size()];
        for (int i = 0; i < uris.length; i++)
        {
            uris[i] = ASN1IA5String.getInstance(locationInfo.getObjectAt(i)).getString();
        }
        return uris;
    }

    public ASN1BitString getSignature()
    {
        return signature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(certID);
        v.add(requestTime);
        v.add(locationInfo);
        v.add(signature);
        return new DERSequence(v);
    }
}
