package org.bouncycastle.asn1.esf;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Signer-Location attribute (RFC3126).
 * 
 * <pre>
 *   SignerLocation ::= SEQUENCE {
 *       countryName        [0] DirectoryString OPTIONAL,
 *       localityName       [1] DirectoryString OPTIONAL,
 *       postalAddress      [2] PostalAddress OPTIONAL }
 *
 *   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
 * </pre>
 */
public class SignerLocation
    extends ASN1Object
{
    private DirectoryString   countryName;
    private DirectoryString   localityName;
    private ASN1Sequence      postalAddress;
    
    private SignerLocation(
        ASN1Sequence seq)
    {
        Enumeration     e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = (ASN1TaggedObject)e.nextElement();

            switch (o.getTagNo())
            {
            case 0:
                this.countryName = DirectoryString.getInstance(o, true);;
                break;
            case 1:
                this.localityName = DirectoryString.getInstance(o, true);
                break;
            case 2:
                if (o.isExplicit())
                {
                    this.postalAddress = ASN1Sequence.getInstance(o, true);
                }
                else    // handle erroneous implicitly tagged sequences
                {
                    this.postalAddress = ASN1Sequence.getInstance(o, false);
                }
                if (postalAddress != null && postalAddress.size() > 6)
                {
                    throw new IllegalArgumentException("postal address must contain less than 6 strings");
                }
                break;
            default:
                throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    private SignerLocation(
        DirectoryString   countryName,
        DirectoryString   localityName,
        ASN1Sequence      postalAddress)
    {
        if (postalAddress != null && postalAddress.size() > 6)
        {
            throw new IllegalArgumentException("postal address must contain less than 6 strings");
        }

        this.countryName = countryName;
        this.localityName = localityName;
        this.postalAddress = postalAddress;
    }

    public SignerLocation(
        DirectoryString   countryName,
        DirectoryString   localityName,
        DirectoryString[] postalAddress)
    {
        this(countryName, localityName, new DERSequence(postalAddress));
    }

    public SignerLocation(
        DERUTF8String   countryName,
        DERUTF8String   localityName,
        ASN1Sequence    postalAddress)
    {
        this(DirectoryString.getInstance(countryName), DirectoryString.getInstance(localityName), postalAddress);
    }

    public static SignerLocation getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof SignerLocation)
        {
            return (SignerLocation)obj;
        }

        return new SignerLocation(ASN1Sequence.getInstance(obj));
    }

    /**
     * Return the countryName DirectoryString
     *
     * @return the countryName, null if absent.
     */
    public DirectoryString getCountry()
    {
        return countryName;
    }

    /**
     * Return the localityName DirectoryString
     *
     * @return the localityName, null if absent.
     */
    public DirectoryString getLocality()
    {
        return localityName;
    }

    /**
     * Return the postalAddress DirectoryStrings
     *
     * @return the postalAddress, null if absent.
     */
    public DirectoryString[] getPostal()
    {
        if (postalAddress == null)
        {
            return null;
        }

        DirectoryString[] dirStrings = new DirectoryString[postalAddress.size()];
        for (int i = 0; i != dirStrings.length; i++)
        {
            dirStrings[i] = DirectoryString.getInstance(postalAddress.getObjectAt(i));
        }

        return dirStrings;
    }

    /**
     * @deprecated use getCountry()
     */
    public DERUTF8String getCountryName()
    {
        if (countryName == null)
        {
            return null;
        }
        return new DERUTF8String(getCountry().getString());
    }

    /**
     * @deprecated use getLocality()
     */
    public DERUTF8String getLocalityName()
    {
        if (localityName == null)
        {
            return null;
        }
        return new DERUTF8String(getLocality().getString());
    }

    public ASN1Sequence getPostalAddress()
    {
        return postalAddress;
    }

    /**
     * <pre>
     *   SignerLocation ::= SEQUENCE {
     *       countryName        [0] DirectoryString OPTIONAL,
     *       localityName       [1] DirectoryString OPTIONAL,
     *       postalAddress      [2] PostalAddress OPTIONAL }
     *
     *   PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
     *   
     *   DirectoryString ::= CHOICE {
     *         teletexString           TeletexString (SIZE (1..MAX)),
     *         printableString         PrintableString (SIZE (1..MAX)),
     *         universalString         UniversalString (SIZE (1..MAX)),
     *         utf8String              UTF8String (SIZE (1.. MAX)),
     *         bmpString               BMPString (SIZE (1..MAX)) }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (countryName != null)
        {
            v.add(new DERTaggedObject(true, 0, countryName));
        }

        if (localityName != null)
        {
            v.add(new DERTaggedObject(true, 1, localityName));
        }

        if (postalAddress != null)
        {
            v.add(new DERTaggedObject(true, 2, postalAddress));
        }

        return new DERSequence(v);
    }
}
