package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class X500NameTest
    extends SimpleTest
{
   String[] subjects =
   {
       "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au,E=webmaster@connect4.com.au",
       "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Certificate Authority,CN=Connect 4 CA,E=webmaster@connect4.com.au",
       "C=AU,ST=QLD,CN=SSLeay/rsa test cert",
       "C=US,O=National Aeronautics and Space Administration,SERIALNUMBER=16+CN=Steve Schoch",
       "E=cooke@issl.atl.hp.com,C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke",
       "O=Sun Microsystems Inc,CN=store.sun.com",
       "unstructuredAddress=192.168.1.33,unstructuredName=pixfirewall.ciscopix.com,CN=pixfirewall.ciscopix.com",
       "CN=*.canal-plus.com,OU=Provided by TBS INTERNET https://www.tbs-certificats.com/,OU=\\ CANAL \\+,O=CANAL\\+DISTRIBUTION,L=issy les moulineaux,ST=Hauts de Seine,C=FR",
       "O=Bouncy Castle,CN=www.bouncycastle.org\\ ",
       "O=Bouncy Castle,CN=c:\\\\fred\\\\bob",
       "C=AU,O=1,OU=2,T=3,CN=4,SERIALNUMBER=5,STREET=6,SERIALNUMBER=7,L=8,ST=9,SURNAME=10,GIVENNAME=11,INITIALS=12," +
           "GENERATION=13,UniqueIdentifier=14,BusinessCategory=15,PostalCode=16,DN=17,Pseudonym=18,PlaceOfBirth=19," +
           "Gender=20,CountryOfCitizenship=21,CountryOfResidence=22,NameAtBirth=23,PostalAddress=24,2.5.4.54=25," +
           "TelephoneNumber=26,Name=27,E=28,unstructuredName=29,unstructuredAddress=30,E=31,DC=32,UID=33",
        "C=DE,L=Berlin,O=Wohnungsbaugenossenschaft \\\"Humboldt-Universität\\\" eG,CN=transfer.wbg-hub.de"
    };

    String[] hexSubjects =
    {
        "CN=\\20Test\\20X,O=\\20Test,C=GB",    // input
        "CN=\\ Test X,O=\\ Test,C=GB",          // expected
        "CN=\\20Test\\20X\\20,O=\\20Test,C=GB",    // input
        "CN=\\ Test X\\ ,O=\\ Test,C=GB"          // expected
    };

    private static final String dnqSubject = "DNQ=Legion of the Bouncy Castle Inc.";

    public String getName()
    {
        return "X500Name";
    }

    private static X500Name fromBytes(byte[] bytes) throws IOException
    {
        return X500Name.getInstance(bytes);
    }

    private ASN1Encodable createEntryValue(ASN1ObjectIdentifier oid, String value)
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(oid, value);
        
        X500Name name = builder.build();

        ASN1Sequence seq = ASN1Sequence.getInstance(name.toASN1Primitive());
        ASN1Set set = ASN1Set.getInstance(seq.getObjectAt(0).toASN1Primitive());
        seq = ASN1Sequence.getInstance(set.getObjectAt(0));

        return seq.getObjectAt(1);
    }

    private ASN1Encodable createEntryValueFromString(ASN1ObjectIdentifier oid, String value)
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(oid, value);

        X500Name name = new X500Name(builder.build().toString());

        ASN1Sequence seq = ASN1Sequence.getInstance(name.toASN1Primitive());
        ASN1Set set = ASN1Set.getInstance(seq.getObjectAt(0).toASN1Primitive());
        seq = ASN1Sequence.getInstance(set.getObjectAt(0));

        return seq.getObjectAt(1);
    }

    private void testEncodingPrintableString(ASN1ObjectIdentifier oid, String value)
    {
        ASN1Encodable converted = createEntryValue(oid, value);
        if (!(converted instanceof ASN1PrintableString))
        {
            fail("encoding for " + oid + " not printable string");
        }
    }

    private void testEncodingIA5String(ASN1ObjectIdentifier oid, String value)
    {
        ASN1Encodable converted = createEntryValue(oid, value);
        if (!(converted instanceof ASN1IA5String))
        {
            fail("encoding for " + oid + " not IA5String");
        }
    }

    private void testEncodingUTF8String(ASN1ObjectIdentifier oid, String value)
        throws IOException
    {
        ASN1Encodable converted = createEntryValue(oid, value);
        if (!(converted instanceof ASN1UTF8String))
        {
            fail("encoding for " + oid + " not UTF8String");
        }
        if (!value.equals((ASN1UTF8String.getInstance(converted.toASN1Primitive().getEncoded()).getString())))
        {
            fail("decoding not correct");
        }
    }

    private void testEncodingGeneralizedTime(ASN1ObjectIdentifier oid, String value)
    {
        ASN1Encodable converted = createEntryValue(oid, value);
        if (!(converted instanceof ASN1GeneralizedTime))
        {
            fail("encoding for " + oid + " not GeneralizedTime");
        }
        converted = createEntryValueFromString(oid, value);
        if (!(converted instanceof ASN1GeneralizedTime))
        {
            fail("encoding for " + oid + " not GeneralizedTime");
        }
    }

    public void performTest()
        throws Exception
    {
        bogusEqualsTest();
        dnQualifierAliasParseTest();
        stateOrProvinceAliasParseTest();
        hexEscapedUTF8ParseTest();
        escapeRoundTripTest();
        turkishLocaleCanonicalizeTest();

        testEncodingPrintableString(BCStyle.C, "AU");
        testEncodingPrintableString(BCStyle.SERIALNUMBER, "123456");
        testEncodingPrintableString(BCStyle.DN_QUALIFIER, "123456");
        testEncodingIA5String(BCStyle.EmailAddress, "test@test.com");
        testEncodingIA5String(BCStyle.DC, "test");
        // correct encoding
        testEncodingGeneralizedTime(BCStyle.DATE_OF_BIRTH, "#180F32303032303132323132323232305A");
        // compatibility encoding
        testEncodingGeneralizedTime(BCStyle.DATE_OF_BIRTH, "20020122122220Z");
        testEncodingUTF8String(BCStyle.CN, "Mörsky");
        testEncodingUTF8String(BCStyle.ORGANIZATION_IDENTIFIER, "Mörsky");
        
        //
        // composite
        //
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        X500Name    name1 = builder.build();

        if (!name1.equals(name1))
        {
            fail("Failed same object test");
        }

        // basic style test
        X500Name dnqName = new X500Name(DNQStyle.INSTANCE, dnqSubject);

        isEquals(dnqName.toString(), "DNQ=Legion of the Bouncy Castle Inc.");
        
//        if (!name1.equals(name1, true))
//        {
//            fail("Failed same object test - in Order");
//        }

        builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        X500Name    name2 = builder.build();

        if (!name1.equals(name2))
        {
            fail("Failed same name test");
        }

//        if (!name1.equals(name2, true))
//        {
//            fail("Failed same name test - in Order");
//        }

        if (name1.hashCode() != name2.hashCode())
        {
            fail("Failed same name test - in Order");
        }

        X500NameBuilder builder1 = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        X500NameBuilder builder2 = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");
        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");

        name1 = builder1.build();
        name2 = builder2.build();

        if (!name1.equals(name2))
        {
            fail("Failed reverse name test");
        }

        if (name1.hashCode() != name2.hashCode())
        {
            fail("Failed reverse name test hashCode");
        }

//        if (name1.equals(name2, true))
//        {
//            fail("Failed reverse name test - in Order");
//        }
//
//        if (!name1.equals(name2, false))
//        {
//            fail("Failed reverse name test - in Order false");
//        }

//        Vector oids = name1.getOIDs();
//        if (!compareVectors(oids, ord1))
//        {
//            fail("oid comparison test");
//        }
       /*
        Vector val1 = new Vector();

        val1.addElement("AU");
        val1.addElement("The Legion of the Bouncy Castle");
        val1.addElement("Melbourne");
        val1.addElement("Victoria");
        val1.addElement("feedback-crypto@bouncycastle.org");

        name1 = new X500Name(ord1, val1);

        Vector values = name1.getValues();
        if (!compareVectors(values, val1))
        {
            fail("value comparison test");
        }

        ord2 = new Vector();

        ord2.addElement(X500Name.ST);
        ord2.addElement(X500Name.ST);
        ord2.addElement(X500Name.L);
        ord2.addElement(X500Name.O);
        ord2.addElement(X500Name.C);

        name1 = new X500Name(ord1, attrs);
        name2 = new X500Name(ord2, attrs);

        if (name1.equals(name2))
        {
            fail("Failed different name test");
        }

        ord2 = new Vector();

        ord2.addElement(X500Name.ST);
        ord2.addElement(X500Name.L);
        ord2.addElement(X500Name.O);
        ord2.addElement(X500Name.C);

        name1 = new X500Name(ord1, attrs);
        name2 = new X500Name(ord2, attrs);

        if (name1.equals(name2))
        {
            fail("Failed subset name test");
        }

        compositeTest();
         */
       /*
        //
        // getValues test
        //
        Vector v1 = name1.getValues(X500Name.O);

        if (v1.size() != 1 || !v1.elementAt(0).equals("The Legion of the Bouncy Castle"))
        {
            fail("O test failed");
        }

        Vector v2 = name1.getValues(X500Name.L);

        if (v2.size() != 1 || !v2.elementAt(0).equals("Melbourne"))
        {
            fail("L test failed");
        }
       */
        //
        // general subjects test
        //
        for (int i = 0; i != subjects.length; i++)
        {
            X500Name name = new X500Name(subjects[i]);
            name = fromBytes(name.getEncoded());
            if (!name.toString().equals(subjects[i]))
            {
                fail("failed regeneration test " + i + " got: " + name.toString() + " expected " + subjects[i]);
            }
        }

        for (int i = 0; i < hexSubjects.length; i += 2)
        {
            X500Name name = new X500Name(hexSubjects[i]);
            name = fromBytes(name.getEncoded());
            if (!name.toString().equals(hexSubjects[i + 1]))
            {
                fail("failed hex regeneration test " + i + " got: " + name.toString() + " expected " + hexSubjects[i + 1]);
            }
        }

        //
        // sort test
        //
        X500Name unsorted = new X500Name("SERIALNUMBER=BBB + CN=AA");

        if (!fromBytes(unsorted.getEncoded()).toString().equals("CN=AA+SERIALNUMBER=BBB"))
        {
            fail("failed sort test 1");
        }

        unsorted = new X500Name("CN=AA + SERIALNUMBER=BBB");

        if (!fromBytes(unsorted.getEncoded()).toString().equals("CN=AA+SERIALNUMBER=BBB"))
        {
            fail("failed sort test 2");
        }

        unsorted = new X500Name("SERIALNUMBER=B + CN=AA");

        if (!fromBytes(unsorted.getEncoded()).toString().equals("SERIALNUMBER=B+CN=AA"))
        {
            fail("failed sort test 3");
        }

        unsorted = new X500Name("CN=AA + SERIALNUMBER=B");

        if (!fromBytes(unsorted.getEncoded()).toString().equals("SERIALNUMBER=B+CN=AA"))
        {
            fail("failed sort test 4");
        }

        //
        // equality tests
        //
        equalityTest(new X500Name("CN=The     Legion"), new X500Name("CN=The Legion"));
        equalityTest(new X500Name("CN=   The Legion"), new X500Name("CN=The Legion"));
        equalityTest(new X500Name("CN=The Legion   "), new X500Name("CN=The Legion"));
        equalityTest(new X500Name("CN=  The     Legion "), new X500Name("CN=The Legion"));
        equalityTest(new X500Name("CN=  the     legion "), new X500Name("CN=The Legion"));

        equalityTest(new X500Name("CN=  the     legion+C=AU, O=Legion "), new X500Name("CN=The Legion+C=AU, O=Legion"));
        // # test

        X500Name n1 = new X500Name("SERIALNUMBER=8,O=ABC,CN=ABC Class 3 CA,C=LT");
        X500Name n2 = new X500Name("2.5.4.5=8,O=ABC,CN=ABC Class 3 CA,C=LT");
        X500Name n3 = new X500Name("2.5.4.5=#130138,O=ABC,CN=ABC Class 3 CA,C=LT");

        equalityTest(n1, n2);
        equalityTest(n2, n3);
        equalityTest(n3, n1);

        n1 = new X500Name("2.5.4.5=#130138,CN=SSC Class 3 CA,O=UAB Skaitmeninio sertifikavimo centras,C=LT");
        n2 = new X500Name("SERIALNUMBER=#130138,CN=SSC Class 3 CA,O=UAB Skaitmeninio sertifikavimo centras,C=LT");
        n3 = fromBytes(Hex.decode("3063310b3009060355040613024c54312f302d060355040a1326"
            + "55414220536b6169746d656e696e696f20736572746966696b6176696d6f2063656e74726173311730150603550403130e53534320436c6173732033204341310a30080603550405130138"));

        equalityTest(n1, n2);
        equalityTest(n2, n3);
        equalityTest(n3, n1);

        n1 = new X500Name("SERIALNUMBER=8,O=XX,CN=ABC Class 3 CA,C=LT");
        n2 = new X500Name("2.5.4.5=8,O=,CN=ABC Class 3 CA,C=LT");

//        if (n1.equals(n2))
//        {
//            fail("empty inequality check failed");
//        }

        n1 = new X500Name("SERIALNUMBER=8,O=,CN=ABC Class 3 CA,C=LT");
        n2 = new X500Name("2.5.4.5=8,O=,CN=ABC Class 3 CA,C=LT");

        equalityTest(n1, n2);

        equalityTest(X500Name.getInstance(BCStrictStyle.INSTANCE, n1), X500Name.getInstance(BCStrictStyle.INSTANCE, n2));

        n2 = new X500Name("C=LT,2.5.4.5=8,O=,CN=ABC Class 3 CA");

        equalityTest(n1, n2);

        if (X500Name.getInstance(BCStrictStyle.INSTANCE, n1).equals(X500Name.getInstance(BCStrictStyle.INSTANCE, n2)))
        {
            fail("strict comparison failed");
        }

        equalityTest(new X500Name(""), new X500Name(""));

        //
        // inequality to sequences
        //
        name1 = new X500Name("CN=The Legion");

        if (name1.equals(new DERSequence()))
        {
            fail("inequality test with sequence");
        }

        if (name1.equals(new DERSequence(new DERSet())))
        {
            fail("inequality test with sequence and set");
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1ObjectIdentifier("1.1"));
        v.add(new ASN1ObjectIdentifier("1.1"));
        if (name1.equals(new DERSequence(new DERSet(new DERSet(v)))))
        {
            fail("inequality test with sequence and bad set");
        }

        if (name1.equals(new DERSequence(new DERSet(new DERSet(v)))))
        {
            fail("inequality test with sequence and bad set");
        }

        if (name1.equals(new DERSequence(new DERSet(new DERSequence()))))
        {
            fail("inequality test with sequence and short sequence");
        }

        if (name1.equals(new DERSequence(new DERSet(new DERSequence()))))
        {
            fail("inequality test with sequence and short sequence");
        }

        v = new ASN1EncodableVector();

        v.add(new ASN1ObjectIdentifier("1.1"));
        v.add(new DERSequence());

        if (name1.equals(new DERSequence(new DERSet(new DERSequence(v)))))
        {
            fail("inequality test with sequence and bad sequence");
        }

        if (name1.equals(null))
        {
            fail("inequality test with null");
        }

//        if (name1.equals(null, true))
//        {
//            fail("inequality test with null");
//        }

        //
        // this is contrived but it checks sorting of sets with equal elements
        //
        unsorted = new X500Name("CN=AA + CN=AA + CN=AA");

        ASN1ObjectIdentifier[] types = unsorted.getAttributeTypes();
        if (types.length != 3 || !types[0].equals(BCStyle.CN) || !types[1].equals(BCStyle.CN) || !types[2].equals(BCStyle.CN))
        {
            fail("types not matched correctly");
        }

        // general type test
        X500Name nested = new X500Name("CN=AA + CN=AA, C=AU");

        types = nested.getAttributeTypes();
        if (types.length != 3 || !types[0].equals(BCStyle.CN) || !types[1].equals(BCStyle.CN) || !types[2].equals(BCStyle.C))
        {
            fail("nested types not matched correctly");
        }
        //
        // tagging test - only works if CHOICE implemented
        //
        ASN1TaggedObject tag = new DERTaggedObject(false, 1, new X500Name("CN=AA"));

        if (!tag.isExplicit())
        {
            fail("failed to explicitly tag CHOICE object");
        }

        X500Name name = X500Name.getInstance(tag, false);

        if (!name.equals(new X500Name("CN=AA")))
        {
            fail("failed to recover tagged name");
        }

        ASN1UTF8String testString = new DERUTF8String("The Legion of the Bouncy Castle");
        byte[] encodedBytes = testString.getEncoded();
        byte[] hexEncodedBytes = Hex.encode(encodedBytes);
        String hexEncodedString = "#" + new String(hexEncodedBytes);

        ASN1UTF8String converted = (ASN1UTF8String)
            new X509DefaultEntryConverter().getConvertedValue(
                BCStyle.L , hexEncodedString);

        if (!converted.equals(testString))
        {
            fail("failed X509DefaultEntryConverter test");
        }

        //
        // try escaped.
        //
        converted = (ASN1UTF8String)
            new X509DefaultEntryConverter().getConvertedValue(
                BCStyle.L , "\\" + hexEncodedString);

        if (!converted.equals(new DERUTF8String(hexEncodedString)))
        {
            fail("failed X509DefaultEntryConverter test got " + converted + " expected: " + hexEncodedString);
        }

        //
        // try a weird value
        //
        X500Name n = new X500Name("CN=\\#nothex#string");

        if (!n.toString().equals("CN=\\#nothex#string"))
        {
            fail("# string not properly escaped.");
        }

        RDN[] vls = n.getRDNs(BCStyle.CN);
        if (vls.length != 1 || !getValue(vls[0]).equals("#nothex#string"))
        {
            fail("escaped # not reduced properly");
        }

        types = n.getAttributeTypes();
        if (types.length != 1 || !types[0].equals(BCStyle.CN))
        {
            fail("type not matched correctly");
        }

        n = new X500Name("CN=\"a+b\"");

        vls = n.getRDNs(BCStyle.CN);
        if (vls.length != 1 || !getValue(vls[0]).equals("a+b"))
        {
            fail("escaped + not reduced properly");
        }

        n = new X500Name("CN=a\\+b");

        vls = n.getRDNs(BCStyle.CN);
        if (vls.length != 1 || !getValue(vls[0]).equals("a+b"))
        {
            fail("escaped + not reduced properly");
        }

        if (!n.toString().equals("CN=a\\+b"))
        {
            fail("+ in string not properly escaped.");
        }

        n = new X500Name("CN=a\\=b");

        vls = n.getRDNs(BCStyle.CN);
        if (vls.length != 1 || !getValue(vls[0]).equals("a=b"))
        {
            fail("escaped = not reduced properly");
        }

        if (!n.toString().equals("CN=a\\=b"))
        {
            fail("= in string not properly escaped.");
        }

        n = new X500Name("TELEPHONENUMBER=\"+61999999999\"");

        vls = n.getRDNs(BCStyle.TELEPHONE_NUMBER);
        if (vls.length != 1 || !getValue(vls[0]).equals("+61999999999"))
        {
            fail("telephonenumber escaped + not reduced properly");
        }

        n = new X500Name("TELEPHONENUMBER=\\+61999999999");

        vls = n.getRDNs(BCStyle.TELEPHONE_NUMBER);
        if (vls.length != 1 || !getValue(vls[0]).equals("+61999999999"))
        {
            fail("telephonenumber escaped + not reduced properly");
        }

        // test query methods
        if (!"E".equals(BCStyle.INSTANCE.oidToDisplayName(BCStyle.EmailAddress)))
        {
            fail("display name for E incorrect");
        }

        String[] aliases = BCStyle.INSTANCE.oidToAttrNames(BCStyle.EmailAddress);
        if (aliases.length != 2)
        {
            fail("no aliases found");
        }
        if (!("e".equals(aliases[0]) || "e".equals(aliases[1])))
        {
            fail("first alias name for E incorrect");
        }
        if (!("emailaddress".equals(aliases[0]) || "emailaddress".equals(aliases[1])))
        {
            fail("second alias name for E incorrect");
        }

        if (BCStyle.INSTANCE.oidToDisplayName(new ASN1ObjectIdentifier("1.2.1")) != null)
        {
            fail("unknown oid matched!");
        }

        if (BCStyle.INSTANCE.oidToAttrNames(new ASN1ObjectIdentifier("1.2.1")).length != 0)
        {
            fail("unknown oid matched aliases!");
        }

        if (!new X500Name("CN=\"  CA1 -   CP.04.03\", OU=Testing, OU=Dod, O=U.S. Government, C=US")
            .equals(new X500Name("CN=\"ca1 - CP.04.03  \", OU=Testing, OU=Dod, O=U.S. Government, C=US")))
        {
            fail("padded equality test failed");
        }

        isTrue(BCStyle.INSTANCE.attrNameToOID("jurisdictionCountry").equals(BCStyle.JURISDICTION_C));
        isTrue(BCStyle.INSTANCE.attrNameToOID("jurisdictionState").equals(BCStyle.JURISDICTION_ST));
        isTrue(BCStyle.INSTANCE.attrNameToOID("jurisdictionLocality").equals(BCStyle.JURISDICTION_L));
    }

    private String getValue(RDN vl)
    {
        return ((ASN1String)vl.getFirst().getValue()).getString();
    }

    /**
     * BCStyle / RFC4519Style now accept "DN", "DNQ" and "dnQualifier"
     * as parser aliases for the dnQualifier attribute (OID 2.5.4.46).
     * The motivating case was that {@code java.security.cert.X509Certificate.getSubjectX500Principal().toString()}
     * emits "DNQ=" on some JDKs (Amazon Corretto 17 observed) and
     * "DNQUALIFIER=" on others, neither of which round-tripped through
     * {@code new X500Name(principal.toString())} under BCStyle's
     * historical "DN" form (issue #1622).
     */
    private void dnQualifierAliasParseTest()
        throws Exception
    {
        String[] aliases = new String[]{ "DN", "DNQ", "dnQualifier", "dn", "dnq", "dnqualifier" };
        for (int i = 0; i != aliases.length; ++i)
        {
            String alias = aliases[i];

            X500Name viaBcStyle = new X500Name(BCStyle.INSTANCE,
                "CN=Foo," + alias + "=ABC123");
            RDN[] rdnsBc = viaBcStyle.getRDNs(BCStyle.DN_QUALIFIER);
            if (rdnsBc.length != 1)
            {
                fail("BCStyle: alias '" + alias
                    + "' did not parse to a single dnQualifier RDN");
            }

            X500Name viaRfc = new X500Name(RFC4519Style.INSTANCE,
                "CN=Foo," + alias + "=ABC123");
            RDN[] rdnsRfc = viaRfc.getRDNs(RFC4519Style.dnQualifier);
            if (rdnsRfc.length != 1)
            {
                fail("RFC4519Style: alias '" + alias
                    + "' did not parse to a single dnQualifier RDN");
            }
        }
    }

    /**
     * BCStyle / RFC4519Style now accept "S" as a parser alias for the
     * stateOrProvinceName attribute (OID 2.5.4.8), in addition to the
     * RFC 2253/4514 short form "ST". Microsoft's CertNameToStr emits "S="
     * for 2.5.4.8 ("This value is different from the RFC 1779 X.500 key
     * name ('ST')."), so DN strings produced by Windows tooling did not
     * round-trip through {@code new X500Name(...)}. Output still uses the
     * canonical "ST" symbol (issue #1301).
     */
    private void stateOrProvinceAliasParseTest()
        throws Exception
    {
        String[] aliases = new String[]{"ST", "st", "S", "s"};
        for (int i = 0; i != aliases.length; ++i)
        {
            String alias = aliases[i];

            X500Name viaBcStyle = new X500Name(BCStyle.INSTANCE,
                "CN=Foo," + alias + "=California");
            RDN[] rdnsBc = viaBcStyle.getRDNs(BCStyle.ST);
            if (rdnsBc.length != 1)
            {
                fail("BCStyle: alias '" + alias
                    + "' did not parse to a single stateOrProvinceName RDN");
            }

            X500Name viaRfc = new X500Name(RFC4519Style.INSTANCE,
                "CN=Foo," + alias + "=California");
            RDN[] rdnsRfc = viaRfc.getRDNs(RFC4519Style.st);
            if (rdnsRfc.length != 1)
            {
                fail("RFC4519Style: alias '" + alias
                    + "' did not parse to a single stateOrProvinceName RDN");
            }
        }

        // output uses the canonical "ST" symbol regardless of the input alias
        X500Name fromS = new X500Name(BCStyle.INSTANCE, "CN=Foo,S=California");
        if (!fromS.toString().equals("CN=Foo,ST=California"))
        {
            fail("BCStyle: 'S' alias did not normalise to ST on output, got: " + fromS);
        }
    }

    /**
     * IETFUtils.canonicalize — and hence X500Name equality / hashCode — folds
     * case through the locale-independent Strings.toLowerCase, not
     * String.toLowerCase(). Under the Turkish locale String.toLowerCase("IT")
     * yields "ıt" (dotless i), which would make c=IT and c=it canonicalize
     * differently and compare unequal. This pins the behaviour to ASCII
     * case-folding regardless of the default locale (issue #1103).
     */
    private void turkishLocaleCanonicalizeTest()
        throws Exception
    {
        Locale turkish = new Locale("tr", "TR");

        // Precondition: confirm the JVM's Turkish locale really does the
        // dotless-i fold (String.toLowerCase("IT") -> "ıt", not "it"),
        // otherwise the test would pass vacuously.
        isTrue("Turkish locale dotless-i fold not active", !"IT".toLowerCase(turkish).equals("it"));

        Locale defaultLocale = Locale.getDefault();
        try
        {
            Locale.setDefault(turkish);

            isTrue("canonicalize must ASCII-fold under Turkish locale", "it".equals(IETFUtils.canonicalize("IT")));

            X500Name upper = new X500Name("CN=ITALY,C=IT");
            X500Name lower = new X500Name("CN=italy,C=it");
            if (!upper.equals(lower))
            {
                fail("X500Name equality is locale-sensitive under Turkish locale");
            }
            if (upper.hashCode() != lower.hashCode())
            {
                fail("X500Name hashCode is locale-sensitive under Turkish locale");
            }
        }
        finally
        {
            Locale.setDefault(defaultLocale);
        }
    }

    private void bogusEqualsTest()
        throws Exception
    {
        // RFC 4514 sec. 3 allows '=' (0x3D) in stringchar without escaping;
        // only the FIRST '=' separates attributeType from attributeValue.
        // (issue #2226 - matches javax.security.auth.x500.X500Principal)
        String[] subjects = new String[]
            {
                "CN=foo=bar",
            "CN==^_^=",
            "CN=a=b=c",
            "CN=\\=^_^\\=",
        };
        String[] expectedValues = new String[]
        {
            "foo=bar",
            "=^_^=",
            "a=b=c",
            "=^_^=",
        };

        for (int i = 0; i != subjects.length; i++)
        {
            X500Name name = new X500Name(subjects[i]);
            String value = ((ASN1String)name.getRDNs()[0].getFirst().getValue()).getString();
            isEquals("unexpected value for " + subjects[i], expectedValues[i], value);
        }

        // a token with no '=' at all is still a malformed RDN
        try
        {
            new X500Name("CN");
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("badly formatted directory string", e.getMessage());
        }
    }

    /**
     * RFC 4514 sec. 2.4 lets any byte be escaped as \HH, and the underlying
     * directoryString is UTF-8 (RFC 5280 sec. 4.1.2.4). A run of consecutive
     * \HH escapes is therefore a UTF-8 byte sequence, never one Java char per
     * pair (issue #1061).
     */
    private void hexEscapedUTF8ParseTest()
        throws Exception
    {
        String[] subjects = new String[]
        {
            "CN=Lu\\C4\\8Di\\C4\\87",        // Lučić
            "CN=M\\C3\\B6rsky",              // Mörsky
            "CN=\\E6\\97\\A5\\E6\\9C\\AC",   // 日本 (three-byte UTF-8)
            "CN=Lu\\C4\\8Di\\C4\\87,O=Acme", // RDN separator flushes the run
        };
        String[] expectedValues = new String[]
        {
            "Lučić",
            "Mörsky",
            "日本",
            "Lučić",
        };

        for (int i = 0; i != subjects.length; i++)
        {
            X500Name name = new X500Name(subjects[i]);
            String value = ((ASN1String)name.getRDNs()[0].getFirst().getValue()).getString();
            isEquals("unexpected value for " + subjects[i], expectedValues[i], value);

            X500Name reparsed = fromBytes(name.getEncoded());
            String reValue = ((ASN1String)reparsed.getRDNs()[0].getFirst().getValue()).getString();
            isEquals("round-trip lost data for " + subjects[i], expectedValues[i], reValue);
        }

        // A lone leading byte without its continuation byte is malformed UTF-8.
        try
        {
            new X500Name("CN=Lu\\C4");
            fail("malformed UTF-8 escape sequence not rejected");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    /**
     * Exercise every branch of {@link IETFUtils} unescape / {@code valueToString}
     * escaping. RFC 4514 sec. 2.4 makes each of {@code , + " \ < > ;} (and a space
     * at either end) an escapable {@code special}; sec. 3 (legacy RFC 2253 quoting)
     * lets a double-quoted value carry those same separators unescaped. For each
     * input we assert both the unescaped attributeValue and that {@code toString()}
     * re-emits the canonical backslash-escaped form (and round-trips).
     */
    private void escapeRoundTripTest()
        throws Exception
    {
        String[][] cases = new String[][]
        {
            // input                value (after unescape)   canonical toString
            { "CN=a\\,b",           "a,b",                   "CN=a\\,b" },          // escaped comma (RDN separator)
            { "CN=a\\;b",           "a;b",                   "CN=a\\;b" },          // escaped semicolon (legacy separator)
            { "CN=a\\<b",           "a<b",                   "CN=a\\<b" },          // escaped less-than
            { "CN=a\\>b",           "a>b",                   "CN=a\\>b" },          // escaped greater-than
            { "CN=a\\\\b",          "a\\b",                  "CN=a\\\\b" },         // escaped backslash
            { "CN=a\\+b",           "a+b",                   "CN=a\\+b" },          // escaped plus (multi-value separator)
            { "CN=a\\=b",           "a=b",                   "CN=a\\=b" },          // escaped equals
            { "CN=a\\\"b",          "a\"b",                  "CN=a\\\"b" },         // escaped quote mid-value
            { "CN=a\\ b",           "a b",                   "CN=a b" },            // escaped interior space (kept, not trimmed)
            { "CN=\"a,b\"",         "a,b",                   "CN=a\\,b" },          // quoting protects the comma separator
            { "CN=\"a;b\"",         "a;b",                   "CN=a\\;b" },          // quoting protects the semicolon
            { "CN=\"a+b\"",         "a+b",                   "CN=a\\+b" },          // quoting protects the plus
            { "CN=\"a\\b\"",        "a\\b",                  "CN=a\\\\b" },         // backslash is literal inside quotes
            { "CN=   a\\+b",        "a+b",                   "CN=a\\+b" },          // leading unescaped spaces are skipped
            { "CN=\\C3\\A9\\+",     "é+",               "CN=é\\+" },      // hex UTF-8 run flushed before escaped special
        };

        for (int i = 0; i != cases.length; i++)
        {
            String input = cases[i][0];

            X500Name name = new X500Name(input);
            String value = getValue(name.getRDNs()[0]);
            isEquals("unescape value for [" + input + "]", cases[i][1], value);

            String str = name.toString();
            isEquals("toString for [" + input + "]", cases[i][2], str);

            // re-parsing the canonical form must yield the same attributeValue
            String reValue = getValue(new X500Name(str).getRDNs()[0]);
            isEquals("round-trip value for [" + input + "]", cases[i][1], reValue);
        }

        // An empty value still parses to an empty string.
        isEquals("empty value", "", getValue(new X500Name("CN=").getRDNs()[0]));

        // Running out of input while still escaping or quoting is malformed. The
        // unterminated-quote and dangling-bare-backslash cases are caught by
        // X500NameTokenizer.nextToken() (escaped/quoted unbalanced at token end);
        // the incomplete-hexpair cases are invisible to the tokenizer (\C looks
        // like a balanced escape) and are caught by IETFUtils.unescape itself.
        // A '\' beginning a hexpair (RFC 4514 sec. 2.4) that isn't completed by a
        // second hex digit used to silently drop the partial digit (and leak state
        // into a later escape); it must throw.
        String[] malformed = new String[]
        {
            "CN=a\\Cz",     // single hex digit then a letter
            "CN=a\\C,O=x",  // single hex digit then the RDN separator
            "CN=a\\C b",    // single hex digit then a space
            "CN=ab\\C",     // single hex digit at end of input
            "CN=a\\C\"b\"", // single hex digit then a quote
            "CN=\\Cz\\AB",  // partial digit must not corrupt a following valid escape
            "CN=abc\\",     // dangling bare backslash at end of input (tokenizer)
            "O=x,CN=abc\\", // dangling bare backslash after a prior RDN (tokenizer)
            "CN=\"abc",     // unterminated quote at end of input (tokenizer)
            "CN=\"abc,O=x", // unterminated quote spanning the RDN separator (tokenizer)
            "CN=\"",        // lone opening quote (tokenizer)

        };
        for (int i = 0; i != malformed.length; i++)
        {
            try
            {
                new X500Name(malformed[i]);
                fail("malformed hex escape not rejected: " + malformed[i]);
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }
    }

    public static class DNQStyle
        extends BCStyle
    {
        public static final DNQStyle INSTANCE = new DNQStyle();

        private DNQStyle()
        {
             defaultLookUp.put("dnq", BCStyle.DN_QUALIFIER);
             defaultSymbols.put(BCStyle.DN_QUALIFIER, "DNQ");
        }
    }

    /*
  private boolean compareVectors(Vector a, Vector b)    // for compatibility with early JDKs
  {
      if (a.size() != b.size())
      {
          return false;
      }

      for (int i = 0; i != a.size(); i++)
      {
          if (!a.elementAt(i).equals(b.elementAt(i)))
          {
              return false;
          }
      }

      return true;
  }

  private void compositeTest()
      throws IOException
  {
      //
      // composite test
      //
      byte[]  enc = Hex.decode("305e310b300906035504061302415531283026060355040a0c1f546865204c6567696f6e206f662074686520426f756e637920436173746c653125301006035504070c094d656c626f75726e653011060355040b0c0a4173636f742056616c65");

      X500Name n = fromBytes(enc);

      if (!n.toString().equals("C=AU,O=The Legion of the Bouncy Castle,L=Melbourne+OU=Ascot Vale"))
      {
          fail("Failed composite to string test got: " + n.toString());
      }

      if (!n.toString(true, X500Name.DefaultSymbols).equals("L=Melbourne+OU=Ascot Vale,O=The Legion of the Bouncy Castle,C=AU"))
      {
          fail("Failed composite to string test got: " + n.toString(true, X500Name.DefaultSymbols));
      }

      n = new X500Name(true, "L=Melbourne+OU=Ascot Vale,O=The Legion of the Bouncy Castle,C=AU");
      if (!n.toString().equals("C=AU,O=The Legion of the Bouncy Castle,L=Melbourne+OU=Ascot Vale"))
      {
          fail("Failed composite to string reversal test got: " + n.toString());
      }

      n = new X500Name("C=AU, O=The Legion of the Bouncy Castle, L=Melbourne + OU=Ascot Vale");

      byte[] enc2 = n.getEncoded();

      if (!Arrays.areEqual(enc, enc2))
      {
          fail("Failed composite string to encoding test");
      }

      //
      // dud name test - handle empty DN without barfing.
      //
      n = new X500Name("C=CH,O=,OU=dummy,CN=mail@dummy.com");

      n = fromBytes(n.getEncoded());
  }
    */
    private void equalityTest(X500Name name1, X500Name name2)
    {
        if (!name1.equals(name2))
        {
            fail("equality test failed for " + name1 + " : " + name2);
        }

        if (name1.hashCode() != name2.hashCode())
        {
            fail("hashCodeTest test failed for " + name1 + " : " + name2);
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new X500NameTest());
    }
}
