package org.bouncycastle.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERSequence;


/**
 * an Iso7816CertificateBody structure.
 * <pre>
 *  CertificateBody ::= SEQUENCE {
 *      // version of the certificate format. Must be 0 (version 1)
 *      CertificateProfileIdentifer         ASN1TaggedObject,
 *      //uniquely identifies the issuinng CA's signature key pair
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of issuer and the sequence number of the key pair.
 *      CertificationAuthorityReference        ASN1TaggedObject,
 *      // stores the encoded public key
 *      PublicKey                            Iso7816PublicKey,
 *      //associates the public key contained in the certificate with a unique name
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of the holder and the sequence number of the key pair.
 *      certificateHolderReference            ASN1TaggedObject,
 *      // Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write
 *      // access rights to data groups storing sensitive data
 *      certificateHolderAuthorization        Iso7816CertificateHolderAuthorization,
 *      // the date of the certificate generation
 *      CertificateEffectiveDate            ASN1TaggedObject,
 *      // the date after wich the certificate expires
 *      certificateExpirationDate            ASN1TaggedObject
 *  }
 * </pre>
 */
public class CertificateBody
    extends ASN1Object
{
    ASN1InputStream seq;
    private ASN1TaggedObject certificateProfileIdentifier;// version of the certificate format. Must be 0 (version 1)
    private ASN1TaggedObject certificationAuthorityReference;//uniquely identifies the issuinng CA's signature key pair
    private PublicKeyDataObject publicKey;// stores the encoded public key
    private ASN1TaggedObject certificateHolderReference;//associates the public key contained in the certificate with a unique name
    private CertificateHolderAuthorization certificateHolderAuthorization;// Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups storing sensitive data
    private ASN1TaggedObject certificateEffectiveDate;// the date of the certificate generation
    private ASN1TaggedObject certificateExpirationDate;// the date after wich the certificate expires
    private int certificateType = 0;// bit field of initialized data. This will tell us if the data are valid.
    private static final int CPI = 0x01;//certificate Profile Identifier
    private static final int CAR = 0x02;//certification Authority Reference
    private static final int PK = 0x04;//public Key
    private static final int CHR = 0x08;//certificate Holder Reference
    private static final int CHA = 0x10;//certificate Holder Authorization
    private static final int CEfD = 0x20;//certificate Effective Date
    private static final int CExD = 0x40;//certificate Expiration Date

    public static final int profileType = 0x7f;//Profile type Certificate
    public static final int requestType = 0x0D;// Request type Certificate

    private void setIso7816CertificateBody(ASN1TaggedObject appSpe)
        throws IOException
    {
        ASN1Sequence content;
        if (appSpe.hasTag(BERTags.APPLICATION, EACTags.CERTIFICATE_CONTENT_TEMPLATE))
        {
            content = ASN1Sequence.getInstance(appSpe.getBaseUniversal(false, BERTags.SEQUENCE));
        }
        else
        {
            throw new IOException("Bad tag : not an iso7816 CERTIFICATE_CONTENT_TEMPLATE");
        }

        Enumeration objs = content.getObjects();
        while (objs.hasMoreElements())
        {
            ASN1TaggedObject aSpe = ASN1TaggedObject.getInstance(objs.nextElement(), BERTags.APPLICATION);

            switch (aSpe.getTagNo())
            {
            case EACTags.INTERCHANGE_PROFILE:
                setCertificateProfileIdentifier(aSpe);
                break;
            case EACTags.ISSUER_IDENTIFICATION_NUMBER:
                setCertificationAuthorityReference(aSpe);
                break;
            case EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE:
                setPublicKey(PublicKeyDataObject.getInstance(aSpe.getBaseUniversal(false, BERTags.SEQUENCE)));
                break;
            case EACTags.CARDHOLDER_NAME:
                setCertificateHolderReference(aSpe);
                break;
            case EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE:
                setCertificateHolderAuthorization(new CertificateHolderAuthorization(aSpe));
                break;
            case EACTags.APPLICATION_EFFECTIVE_DATE:
                setCertificateEffectiveDate(aSpe);
                break;
            case EACTags.APPLICATION_EXPIRATION_DATE:
                setCertificateExpirationDate(aSpe);
                break;
            default:
                certificateType = 0;
                throw new IOException("Not a valid iso7816 ASN1TaggedObject tag " + aSpe.getTagNo());
            }
        }
    }

    /**
     * builds an Iso7816CertificateBody by settings each parameters.
     *
     * @param certificateProfileIdentifier
     * @param certificationAuthorityReference
     *
     * @param publicKey
     * @param certificateHolderReference
     * @param certificateHolderAuthorization
     * @param certificateEffectiveDate
     * @param certificateExpirationDate
     */
    public CertificateBody(
        ASN1TaggedObject certificateProfileIdentifier,
        CertificationAuthorityReference certificationAuthorityReference,
        PublicKeyDataObject publicKey,
        CertificateHolderReference certificateHolderReference,
        CertificateHolderAuthorization certificateHolderAuthorization,
        PackedDate certificateEffectiveDate,
        PackedDate certificateExpirationDate
    )
    {
        setCertificateProfileIdentifier(certificateProfileIdentifier);
        setCertificationAuthorityReference(EACTagged.create(EACTags.ISSUER_IDENTIFICATION_NUMBER, certificationAuthorityReference.getEncoded()));
        setPublicKey(publicKey);
        setCertificateHolderReference(EACTagged.create(EACTags.CARDHOLDER_NAME, certificateHolderReference.getEncoded()));
        setCertificateHolderAuthorization(certificateHolderAuthorization);
        setCertificateEffectiveDate(EACTagged.create(EACTags.APPLICATION_EFFECTIVE_DATE, certificateEffectiveDate.getEncoding()));
        setCertificateExpirationDate(EACTagged.create(EACTags.APPLICATION_EXPIRATION_DATE, certificateExpirationDate.getEncoding()));
    }

    /**
     * builds an Iso7816CertificateBody with an ASN1InputStream.
     *
     * @param obj ASN1TaggedObject containing the whole body.
     * @throws IOException if the body is not valid.
     */
    private CertificateBody(ASN1TaggedObject obj)
        throws IOException
    {
        setIso7816CertificateBody(obj);
    }

    /**
     * create a profile type Iso7816CertificateBody.
     *
     * @return return the "profile" type certificate body.
     * @throws IOException if the ASN1TaggedObject cannot be created.
     */
    private ASN1Primitive profileToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(certificateProfileIdentifier);
        v.add(certificationAuthorityReference);
        v.add(EACTagged.create(EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, publicKey));
        v.add(certificateHolderReference);
        v.add(certificateHolderAuthorization);
        v.add(certificateEffectiveDate);
        v.add(certificateExpirationDate);
        return EACTagged.create(EACTags.CERTIFICATE_CONTENT_TEMPLATE, new DERSequence(v));
    }

    private void setCertificateProfileIdentifier(ASN1TaggedObject certificateProfileIdentifier)
        throws IllegalArgumentException
    {
        if (certificateProfileIdentifier.hasTag(BERTags.APPLICATION, EACTags.INTERCHANGE_PROFILE))
        {
            this.certificateProfileIdentifier = certificateProfileIdentifier;
            certificateType |= CPI;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.INTERCHANGE_PROFILE tag :" + certificateProfileIdentifier.getTagNo());
        }
    }

    private void setCertificateHolderReference(ASN1TaggedObject certificateHolderReference)
        throws IllegalArgumentException
    {
        if (certificateHolderReference.hasTag(BERTags.APPLICATION, EACTags.CARDHOLDER_NAME))
        {
            this.certificateHolderReference = certificateHolderReference;
            certificateType |= CHR;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.CARDHOLDER_NAME tag");
        }
    }

    /**
     * set the CertificationAuthorityReference.
     *
     * @param certificationAuthorityReference
     *         the ASN1TaggedObject containing the CertificationAuthorityReference.
     * @throws IllegalArgumentException if the ASN1TaggedObject is not valid.
     */
    private void setCertificationAuthorityReference(
        ASN1TaggedObject certificationAuthorityReference)
        throws IllegalArgumentException
    {
        if (certificationAuthorityReference.hasTag(BERTags.APPLICATION, EACTags.ISSUER_IDENTIFICATION_NUMBER))
        {
            this.certificationAuthorityReference = certificationAuthorityReference;
            certificateType |= CAR;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.ISSUER_IDENTIFICATION_NUMBER tag");
        }
    }

    /**
     * set the public Key
     *
     * @param publicKey : the ASN1TaggedObject containing the public key
     * @throws java.io.IOException
     */
    private void setPublicKey(PublicKeyDataObject publicKey)
    {
        this.publicKey = PublicKeyDataObject.getInstance(publicKey);
        this.certificateType |= PK;
    }

    /**
     * create a request type Iso7816CertificateBody.
     *
     * @return return the "request" type certificate body.
     * @throws IOException if the ASN1TaggedObject cannot be created.
     */
    private ASN1Primitive requestToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(certificateProfileIdentifier);
        v.add(EACTagged.create(EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, publicKey));
        v.add(certificateHolderReference);
        return EACTagged.create(EACTags.CERTIFICATE_CONTENT_TEMPLATE, new DERSequence(v));
    }

    /**
     * create a "request" or "profile" type Iso7816CertificateBody according to the variables sets.
     *
     * @return return the ASN1Primitive representing the "request" or "profile" type certificate body.
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            if (certificateType == profileType)
            {
                return profileToASN1Object();
            }
            if (certificateType == requestType)
            {
                return requestToASN1Object();
            }
        }
        catch (IOException e)
        {
            return null;
        }
        return null;
    }

    /**
     * gives the type of the certificate (value should be profileType or requestType if all data are set).
     *
     * @return the int representing the data already set.
     */
    public int getCertificateType()
    {
        return certificateType;
    }

    /**
     * Gives an instance of Iso7816CertificateBody taken from Object obj
     *
     * @param obj is the Object to extract the certificate body from.
     * @return the Iso7816CertificateBody taken from Object obj.
     * @throws IOException if object is not valid.
     */
    public static CertificateBody getInstance(Object obj)
        throws IOException
    {
        if (obj instanceof CertificateBody)
        {
            return (CertificateBody)obj;
        }
        else if (obj != null)
        {
            return new CertificateBody(ASN1TaggedObject.getInstance(obj, BERTags.APPLICATION));
        }

        return null;
    }

    /**
     * @return the date of the certificate generation
     */
    public PackedDate getCertificateEffectiveDate()
    {
        if ((this.certificateType & CertificateBody.CEfD) ==
            CertificateBody.CEfD)
        {
            return new PackedDate(
                ASN1OctetString.getInstance(certificateEffectiveDate.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets());
        }
        return null;
    }

    /**
     * set the date of the certificate generation
     *
     * @param ced ASN1TaggedObject containing the date of the certificate generation
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EFFECTIVE_DATE
     */
    private void setCertificateEffectiveDate(ASN1TaggedObject ced)
        throws IllegalArgumentException
    {
        if (ced.hasTag(BERTags.APPLICATION, EACTags.APPLICATION_EFFECTIVE_DATE))
        {
            this.certificateEffectiveDate = ced;
            certificateType |= CEfD;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EFFECTIVE_DATE tag :" + ced.getTagNo());
        }
    }

    /**
     * @return the date after wich the certificate expires
     */
    public PackedDate getCertificateExpirationDate()
        throws IOException
    {
        if ((this.certificateType & CertificateBody.CExD) ==
            CertificateBody.CExD)
        {
            return new PackedDate(
                ASN1OctetString.getInstance(certificateEffectiveDate.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets());
        }
        throw new IOException("certificate Expiration Date not set");
    }

    /**
     * set the date after wich the certificate expires
     *
     * @param ced ASN1TaggedObject containing the date after wich the certificate expires
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EXPIRATION_DATE
     */
    private void setCertificateExpirationDate(ASN1TaggedObject ced)
        throws IllegalArgumentException
    {
        if (ced.hasTag(BERTags.APPLICATION, EACTags.APPLICATION_EXPIRATION_DATE))
        {
            this.certificateExpirationDate = ced;
            certificateType |= CExD;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EXPIRATION_DATE tag");
        }
    }

    /**
     * the Iso7816CertificateHolderAuthorization encodes the role of the holder
     * (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups
     * storing sensitive data. This functions returns the Certificate Holder
     * Authorization
     *
     * @return the Iso7816CertificateHolderAuthorization
     */
    public CertificateHolderAuthorization getCertificateHolderAuthorization()
        throws IOException
    {
        if ((this.certificateType & CertificateBody.CHA) ==
            CertificateBody.CHA)
        {
            return certificateHolderAuthorization;
        }
        throw new IOException("Certificate Holder Authorisation not set");
    }

    /**
     * set the CertificateHolderAuthorization
     *
     * @param cha the Certificate Holder Authorization
     */
    private void setCertificateHolderAuthorization(
        CertificateHolderAuthorization cha)
    {
        this.certificateHolderAuthorization = cha;
        certificateType |= CHA;
    }

    /**
     * certificateHolderReference : associates the public key contained in the certificate with a unique name
     *
     * @return the certificateHolderReference.
     */
    public CertificateHolderReference getCertificateHolderReference()
    {
        return new CertificateHolderReference(
            ASN1OctetString.getInstance(certificateHolderReference.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets());
    }

    /**
     * CertificateProfileIdentifier : version of the certificate format. Must be 0 (version 1)
     *
     * @return the CertificateProfileIdentifier
     */
    public ASN1TaggedObject getCertificateProfileIdentifier()
    {
        return certificateProfileIdentifier;
    }

    /**
     * get the certificationAuthorityReference
     * certificationAuthorityReference : uniquely identifies the issuinng CA's signature key pair
     *
     * @return the certificationAuthorityReference
     */
    public CertificationAuthorityReference getCertificationAuthorityReference()
        throws IOException
    {
        if ((this.certificateType & CertificateBody.CAR) ==
            CertificateBody.CAR)
        {
            return new CertificationAuthorityReference(
                ASN1OctetString.getInstance(certificationAuthorityReference.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets());
        }
        throw new IOException("Certification authority reference not set");
    }

    /**
     * @return the PublicKey
     */
    public PublicKeyDataObject getPublicKey()
    {
        return publicKey;
    }
}
