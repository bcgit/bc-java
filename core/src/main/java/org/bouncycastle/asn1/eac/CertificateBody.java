package org.bouncycastle.asn1.eac;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;


/**
 * an Iso7816CertificateBody structure.
 * <pre>
 *  CertificateBody ::= SEQUENCE {
 *      // version of the certificate format. Must be 0 (version 1)
 *      CertificateProfileIdentifer         ASN1ApplicationSpecific,
 *      //uniquely identifies the issuinng CA's signature key pair
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of issuer and the sequence number of the key pair.
 *      CertificationAuthorityReference        ASN1ApplicationSpecific,
 *      // stores the encoded public key
 *      PublicKey                            Iso7816PublicKey,
 *      //associates the public key contained in the certificate with a unique name
 *      // contains the iso3166-1 alpha2 encoded country code, the
 *      // name of the holder and the sequence number of the key pair.
 *      certificateHolderReference            ASN1ApplicationSpecific,
 *      // Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write
 *      // access rights to data groups storing sensitive data
 *      certificateHolderAuthorization        Iso7816CertificateHolderAuthorization,
 *      // the date of the certificate generation
 *      CertificateEffectiveDate            ASN1ApplicationSpecific,
 *      // the date after wich the certificate expires
 *      certificateExpirationDate            ASN1ApplicationSpecific
 *  }
 * </pre>
 */
public class CertificateBody
    extends ASN1Object
{
    ASN1InputStream seq;
    private ASN1ApplicationSpecific certificateProfileIdentifier;// version of the certificate format. Must be 0 (version 1)
    private ASN1ApplicationSpecific certificationAuthorityReference;//uniquely identifies the issuinng CA's signature key pair
    private PublicKeyDataObject publicKey;// stores the encoded public key
    private ASN1ApplicationSpecific certificateHolderReference;//associates the public key contained in the certificate with a unique name
    private CertificateHolderAuthorization certificateHolderAuthorization;// Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups storing sensitive data
    private ASN1ApplicationSpecific certificateEffectiveDate;// the date of the certificate generation
    private ASN1ApplicationSpecific certificateExpirationDate;// the date after wich the certificate expires
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

    private void setIso7816CertificateBody(ASN1ApplicationSpecific appSpe)
        throws IOException
    {
        byte[] content;
        if (appSpe.getApplicationTag() == EACTags.CERTIFICATE_CONTENT_TEMPLATE)
        {
            content = appSpe.getContents();
        }
        else
        {
            throw new IOException("Bad tag : not an iso7816 CERTIFICATE_CONTENT_TEMPLATE");
        }
        ASN1InputStream aIS = new ASN1InputStream(content);
        ASN1Primitive obj;
        while ((obj = aIS.readObject()) != null)
        {
            ASN1ApplicationSpecific aSpe;

            if (obj instanceof ASN1ApplicationSpecific)
            {
                aSpe = (ASN1ApplicationSpecific)obj;
            }
            else
            {
                throw new IOException("Not a valid iso7816 content : not a ASN1ApplicationSpecific Object :" + EACTags.encodeTag(appSpe) + obj.getClass());
            }
            switch (aSpe.getApplicationTag())
            {
            case EACTags.INTERCHANGE_PROFILE:
                setCertificateProfileIdentifier(aSpe);
                break;
            case EACTags.ISSUER_IDENTIFICATION_NUMBER:
                setCertificationAuthorityReference(aSpe);
                break;
            case EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE:
                setPublicKey(PublicKeyDataObject.getInstance(aSpe.getObject(BERTags.SEQUENCE)));
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
                throw new IOException("Not a valid iso7816 ASN1ApplicationSpecific tag " + aSpe.getApplicationTag());
            }
        }
        aIS.close();
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
        ASN1ApplicationSpecific certificateProfileIdentifier,
        CertificationAuthorityReference certificationAuthorityReference,
        PublicKeyDataObject publicKey,
        CertificateHolderReference certificateHolderReference,
        CertificateHolderAuthorization certificateHolderAuthorization,
        PackedDate certificateEffectiveDate,
        PackedDate certificateExpirationDate
    )
    {
        setCertificateProfileIdentifier(certificateProfileIdentifier);
        setCertificationAuthorityReference(new DERApplicationSpecific(
            EACTags.ISSUER_IDENTIFICATION_NUMBER, certificationAuthorityReference.getEncoded()));
        setPublicKey(publicKey);
        setCertificateHolderReference(new DERApplicationSpecific(
            EACTags.CARDHOLDER_NAME, certificateHolderReference.getEncoded()));
        setCertificateHolderAuthorization(certificateHolderAuthorization);
        try
        {
            setCertificateEffectiveDate(new DERApplicationSpecific(
                false, EACTags.APPLICATION_EFFECTIVE_DATE, new DEROctetString(certificateEffectiveDate.getEncoding())));
            setCertificateExpirationDate(new DERApplicationSpecific(
                false, EACTags.APPLICATION_EXPIRATION_DATE, new DEROctetString(certificateExpirationDate.getEncoding())));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("unable to encode dates: " + e.getMessage());
        }
    }

    /**
     * builds an Iso7816CertificateBody with an ASN1InputStream.
     *
     * @param obj ASN1ApplicationSpecific containing the whole body.
     * @throws IOException if the body is not valid.
     */
    private CertificateBody(ASN1ApplicationSpecific obj)
        throws IOException
    {
        setIso7816CertificateBody(obj);
    }

    /**
     * create a profile type Iso7816CertificateBody.
     *
     * @return return the "profile" type certificate body.
     * @throws IOException if the ASN1ApplicationSpecific cannot be created.
     */
    private ASN1Primitive profileToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(certificateProfileIdentifier);
        v.add(certificationAuthorityReference);
        v.add(new DERApplicationSpecific(false, EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, publicKey));
        v.add(certificateHolderReference);
        v.add(certificateHolderAuthorization);
        v.add(certificateEffectiveDate);
        v.add(certificateExpirationDate);
        return new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
    }

    private void setCertificateProfileIdentifier(ASN1ApplicationSpecific certificateProfileIdentifier)
        throws IllegalArgumentException
    {
        if (certificateProfileIdentifier.getApplicationTag() == EACTags.INTERCHANGE_PROFILE)
        {
            this.certificateProfileIdentifier = certificateProfileIdentifier;
            certificateType |= CPI;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.INTERCHANGE_PROFILE tag :" + EACTags.encodeTag(certificateProfileIdentifier));
        }
    }

    private void setCertificateHolderReference(ASN1ApplicationSpecific certificateHolderReference)
        throws IllegalArgumentException
    {
        if (certificateHolderReference.getApplicationTag() == EACTags.CARDHOLDER_NAME)
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
     *         the ASN1ApplicationSpecific containing the CertificationAuthorityReference.
     * @throws IllegalArgumentException if the ASN1ApplicationSpecific is not valid.
     */
    private void setCertificationAuthorityReference(
        ASN1ApplicationSpecific certificationAuthorityReference)
        throws IllegalArgumentException
    {
        if (certificationAuthorityReference.getApplicationTag() == EACTags.ISSUER_IDENTIFICATION_NUMBER)
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
     * @param publicKey : the ASN1ApplicationSpecific containing the public key
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
     * @throws IOException if the ASN1ApplicationSpecific cannot be created.
     */
    private ASN1Primitive requestToASN1Object()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(certificateProfileIdentifier);
        v.add(new DERApplicationSpecific(false, EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, publicKey));
        v.add(certificateHolderReference);
        return new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
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
            return new CertificateBody(ASN1ApplicationSpecific.getInstance(obj));
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
            return new PackedDate(certificateEffectiveDate.getContents());
        }
        return null;
    }

    /**
     * set the date of the certificate generation
     *
     * @param ced ASN1ApplicationSpecific containing the date of the certificate generation
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EFFECTIVE_DATE
     */
    private void setCertificateEffectiveDate(ASN1ApplicationSpecific ced)
        throws IllegalArgumentException
    {
        if (ced.getApplicationTag() == EACTags.APPLICATION_EFFECTIVE_DATE)
        {
            this.certificateEffectiveDate = ced;
            certificateType |= CEfD;
        }
        else
        {
            throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EFFECTIVE_DATE tag :" + EACTags.encodeTag(ced));
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
            return new PackedDate(certificateExpirationDate.getContents());
        }
        throw new IOException("certificate Expiration Date not set");
    }

    /**
     * set the date after wich the certificate expires
     *
     * @param ced ASN1ApplicationSpecific containing the date after wich the certificate expires
     * @throws IllegalArgumentException if the tag is not Iso7816Tags.APPLICATION_EXPIRATION_DATE
     */
    private void setCertificateExpirationDate(ASN1ApplicationSpecific ced)
        throws IllegalArgumentException
    {
        if (ced.getApplicationTag() == EACTags.APPLICATION_EXPIRATION_DATE)
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
        return new CertificateHolderReference(certificateHolderReference.getContents());
    }

    /**
     * CertificateProfileIdentifier : version of the certificate format. Must be 0 (version 1)
     *
     * @return the CertificateProfileIdentifier
     */
    public ASN1ApplicationSpecific getCertificateProfileIdentifier()
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
            return new CertificationAuthorityReference(certificationAuthorityReference.getContents());
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
