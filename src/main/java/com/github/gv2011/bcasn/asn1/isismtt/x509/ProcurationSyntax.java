package com.github.gv2011.bcasn.asn1.isismtt.x509;

import java.util.Enumeration;

import com.github.gv2011.bcasn.asn1.ASN1Encodable;
import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DERPrintableString;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.DERTaggedObject;
import com.github.gv2011.bcasn.asn1.x500.DirectoryString;
import com.github.gv2011.bcasn.asn1.x509.GeneralName;
import com.github.gv2011.bcasn.asn1.x509.IssuerSerial;

/**
 * Attribute to indicate that the certificate holder may sign in the name of a
 * third person.
 * <p>
 * ISIS-MTT PROFILE: The corresponding ProcurationSyntax contains either the
 * name of the person who is represented (subcomponent thirdPerson) or a
 * reference to his/her base certificate (in the component signingFor,
 * subcomponent certRef), furthermore the optional components country and
 * typeSubstitution to indicate the country whose laws apply, and respectively
 * the type of procuration (e.g. manager, procuration, custody).
 * <p>
 * ISIS-MTT PROFILE: The GeneralName MUST be of type directoryName and MAY only
 * contain: - RFC3039 attributes, except pseudonym (countryName, commonName,
 * surname, givenName, serialNumber, organizationName, organizationalUnitName,
 * stateOrProvincename, localityName, postalAddress) and - SubjectDirectoryName
 * attributes (title, dateOfBirth, placeOfBirth, gender, countryOfCitizenship,
 * countryOfResidence and NameAtBirth).
 * 
 * <pre>
 *               ProcurationSyntax ::= SEQUENCE {
 *                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
 *                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
 *                 signingFor [3] EXPLICIT SigningFor 
 *               }
 *               
 *               SigningFor ::= CHOICE 
 *               { 
 *                 thirdPerson GeneralName,
 *                 certRef IssuerSerial 
 *               }
 * </pre>
 * 
 */
public class ProcurationSyntax
    extends ASN1Object
{
    private String country;
    private DirectoryString typeOfSubstitution;

    private GeneralName thirdPerson;
    private IssuerSerial certRef;

    public static ProcurationSyntax getInstance(Object obj)
    {
        if (obj == null || obj instanceof ProcurationSyntax)
        {
            return (ProcurationSyntax)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new ProcurationSyntax((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
            + obj.getClass().getName());
    }

    /**
     * Constructor from ASN1Sequence.
     * <p>
     * The sequence is of type ProcurationSyntax:
     * <pre>
     *               ProcurationSyntax ::= SEQUENCE {
     *                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
     *                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
     *                 signingFor [3] EXPLICIT SigningFor
     *               }
     *
     *               SigningFor ::= CHOICE
     *               {
     *                 thirdPerson GeneralName,
     *                 certRef IssuerSerial
     *               }
     * </pre>
     * </p>
     * @param seq The ASN.1 sequence.
     */
    private ProcurationSyntax(ASN1Sequence seq)
    {
        if (seq.size() < 1 || seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo())
            {
                case 1:
                    country = DERPrintableString.getInstance(o, true).getString();
                    break;
                case 2:
                    typeOfSubstitution = DirectoryString.getInstance(o, true);
                    break;
                case 3:
                    ASN1Encodable signingFor = o.getObject();
                    if (signingFor instanceof ASN1TaggedObject)
                    {
                        thirdPerson = GeneralName.getInstance(signingFor);
                    }
                    else
                    {
                        certRef = IssuerSerial.getInstance(signingFor);
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
            }
        }
    }

    /**
     * Constructor from a given details.
     * <p>
     * Either <code>generalName</code> or <code>certRef</code> MUST be
     * <code>null</code>.
     *
     * @param country            The country code whose laws apply.
     * @param typeOfSubstitution The type of procuration.
     * @param certRef            Reference to certificate of the person who is represented.
     */
    public ProcurationSyntax(
        String country,
        DirectoryString typeOfSubstitution,
        IssuerSerial certRef)
    {
        this.country = country;
        this.typeOfSubstitution = typeOfSubstitution;
        this.thirdPerson = null;
        this.certRef = certRef;
    }

    /**
     * Constructor from a given details.
     * <p>
     * Either <code>generalName</code> or <code>certRef</code> MUST be
     * <code>null</code>.
     *
     * @param country            The country code whose laws apply.
     * @param typeOfSubstitution The type of procuration.
     * @param thirdPerson        The GeneralName of the person who is represented.
     */
    public ProcurationSyntax(
        String country,
        DirectoryString typeOfSubstitution,
        GeneralName thirdPerson)
    {
        this.country = country;
        this.typeOfSubstitution = typeOfSubstitution;
        this.thirdPerson = thirdPerson;
        this.certRef = null;
    }

    public String getCountry()
    {
        return country;
    }

    public DirectoryString getTypeOfSubstitution()
    {
        return typeOfSubstitution;
    }

    public GeneralName getThirdPerson()
    {
        return thirdPerson;
    }

    public IssuerSerial getCertRef()
    {
        return certRef;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *               ProcurationSyntax ::= SEQUENCE {
     *                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
     *                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
     *                 signingFor [3] EXPLICIT SigningFor
     *               }
     *
     *               SigningFor ::= CHOICE
     *               {
     *                 thirdPerson GeneralName,
     *                 certRef IssuerSerial
     *               }
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        if (country != null)
        {
            vec.add(new DERTaggedObject(true, 1, new DERPrintableString(country, true)));
        }
        if (typeOfSubstitution != null)
        {
            vec.add(new DERTaggedObject(true, 2, typeOfSubstitution));
        }
        if (thirdPerson != null)
        {
            vec.add(new DERTaggedObject(true, 3, thirdPerson));
        }
        else
        {
            vec.add(new DERTaggedObject(true, 3, certRef));
        }

        return new DERSequence(vec);
    }
}
