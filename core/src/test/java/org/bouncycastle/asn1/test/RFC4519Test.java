package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class RFC4519Test
    extends SimpleTest
{
    static String[] attributeTypes =
        {
            "businessCategory",
            "c",
            "cn",
            "dc",
            "description",
            "destinationIndicator",
            "distinguishedName",
            "dnQualifier",
            "enhancedSearchGuide",
            "facsimileTelephoneNumber",
            "generationQualifier",
            "givenName",
            "houseIdentifier",
            "initials",
            "internationalISDNNumber",
            "l",
            "member",
            "name",
            "o",
            "ou",
            "owner",
            "physicalDeliveryOfficeName",
            "postalAddress",
            "postalCode",
            "postOfficeBox",
            "preferredDeliveryMethod",
            "registeredAddress",
            "roleOccupant",
            "searchGuide",
            "seeAlso",
            "serialNumber",
            "sn",
            "st",
            "street",
            "telephoneNumber",
            "teletexTerminalIdentifier",
            "telexNumber",
            "title",
            "uid",
            "uniqueMember",
            "userPassword",
            "x121Address",
            "x500UniqueIdentifier"
        };

    static ASN1ObjectIdentifier[] attributeTypeOIDs =
        {
            new ASN1ObjectIdentifier("2.5.4.15"),
            new ASN1ObjectIdentifier("2.5.4.6"),
            new ASN1ObjectIdentifier("2.5.4.3"),
            new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25"),
            new ASN1ObjectIdentifier("2.5.4.13"),
            new ASN1ObjectIdentifier("2.5.4.27"),
            new ASN1ObjectIdentifier("2.5.4.49"),
            new ASN1ObjectIdentifier("2.5.4.46"),
            new ASN1ObjectIdentifier("2.5.4.47"),
            new ASN1ObjectIdentifier("2.5.4.23"),
            new ASN1ObjectIdentifier("2.5.4.44"),
            new ASN1ObjectIdentifier("2.5.4.42"),
            new ASN1ObjectIdentifier("2.5.4.51"),
            new ASN1ObjectIdentifier("2.5.4.43"),
            new ASN1ObjectIdentifier("2.5.4.25"),
            new ASN1ObjectIdentifier("2.5.4.7"),
            new ASN1ObjectIdentifier("2.5.4.31"),
            new ASN1ObjectIdentifier("2.5.4.41"),
            new ASN1ObjectIdentifier("2.5.4.10"),
            new ASN1ObjectIdentifier("2.5.4.11"),
            new ASN1ObjectIdentifier("2.5.4.32"),
            new ASN1ObjectIdentifier("2.5.4.19"),
            new ASN1ObjectIdentifier("2.5.4.16"),
            new ASN1ObjectIdentifier("2.5.4.17"),
            new ASN1ObjectIdentifier("2.5.4.18"),
            new ASN1ObjectIdentifier("2.5.4.28"),
            new ASN1ObjectIdentifier("2.5.4.26"),
            new ASN1ObjectIdentifier("2.5.4.33"),
            new ASN1ObjectIdentifier("2.5.4.14"),
            new ASN1ObjectIdentifier("2.5.4.34"),
            new ASN1ObjectIdentifier("2.5.4.5"),
            new ASN1ObjectIdentifier("2.5.4.4"),
            new ASN1ObjectIdentifier("2.5.4.8"),
            new ASN1ObjectIdentifier("2.5.4.9"),
            new ASN1ObjectIdentifier("2.5.4.20"),
            new ASN1ObjectIdentifier("2.5.4.22"),
            new ASN1ObjectIdentifier("2.5.4.21"),
            new ASN1ObjectIdentifier("2.5.4.12"),
            new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1"),
            new ASN1ObjectIdentifier("2.5.4.50"),
            new ASN1ObjectIdentifier("2.5.4.35"),
            new ASN1ObjectIdentifier("2.5.4.24"),
            new ASN1ObjectIdentifier("2.5.4.45")
        };

    public String getName()
    {
        return "RFC4519Test";
    }

    public void performTest()
        throws Exception
    {
        X500NameStyle style = RFC4519Style.INSTANCE;

        for (int i = 0; i != attributeTypes.length; i++)
        {
            if (!attributeTypeOIDs[i].equals(style.attrNameToOID(attributeTypes[i])))
            {
                fail("mismatch for " + attributeTypes[i]);
            }
        }

        byte[] enc = Hex.decode("305e310b300906035504061302415531283026060355040a0c1f546865204c6567696f6e206f662074686520426f756e637920436173746c653125301006035504070c094d656c626f75726e653011060355040b0c0a4173636f742056616c65");

        X500Name n = X500Name.getInstance(style, X500Name.getInstance(enc));

        if (!n.toString().equals("l=Melbourne+ou=Ascot Vale,o=The Legion of the Bouncy Castle,c=AU"))
        {
            fail("Failed composite to string test got: " + n.toString());
        }

        n = new X500Name(style, "l=Melbourne+ou=Ascot Vale,o=The Legion of the Bouncy Castle,c=AU");

        if (!Arrays.areEqual(n.getEncoded(), enc))
        {
            fail("re-encoding test after parse failed");
        }
    }


    public static void main(
        String[] args)
    {
        runTest(new RFC4519Test());
    }
}
