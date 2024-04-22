package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLBitString;
import org.bouncycastle.asn1.DLExternal;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Class checking the correct functionality of DLExternal
 */
public class DLExternalTest
    extends SimpleTest
{

    /**
     * Checks that the values are correctly instantiated
     *
     * @throws Exception Will be thrown if there was an
     *                   error while performing the test
     */
    public void testInstantiationByVector()
        throws Exception
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        String dvdType;
        String ecType;
        try
        {
            new DLExternal(new DLSequence(vec));
            fail("exception expected");
        }
        catch (IllegalArgumentException iae)
        {
            isEquals("check message", "too few objects in input sequence", iae.getMessage());
        }

        vec.add(new DERUTF8String("something completely different"));
        try
        {
            new DLExternal(new DLSequence(vec));
            fail("exception expected");
        }
        catch (IllegalArgumentException iae)
        {
            isEquals("check message", "too few objects in input sequence", iae.getMessage());
        }
        vec.add(new DLTaggedObject(true, 0, new ASN1Integer(1234567890L)));

        DLExternal dle = new DLExternal(new DLSequence(vec));

        isEquals("check direct reference", null, dle.getDirectReference());
        isEquals("check indirect reference", null, dle.getIndirectReference());
        isTrue("check data value descriptor", dle.getDataValueDescriptor() != null);
        dvdType = dle.getDataValueDescriptor().getClass().getName();
        isEquals("check type of value descriptor: " + dvdType, DERUTF8String.class.getName(), dvdType);
        isEquals("check value", "something completely different", ((ASN1UTF8String)dle.getDataValueDescriptor()).getString());
        isEquals("check encoding", 0, dle.getEncoding());
        isTrue("check existence of external content", dle.getExternalContent() != null);
        ecType = dle.getExternalContent().getClass().getName();
        isEquals("check type of external content: " + ecType, ASN1Integer.class.getName(), ecType);
        isEquals("check value of external content", "1234567890", ((ASN1Integer)dle.getExternalContent()).getValue().toString());

        vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(9L));
        vec.add(new DERUTF8String("something completely different"));
        vec.add(new DLTaggedObject(true, 0, new ASN1Integer(1234567890L)));
        dle = new DLExternal(vec);

        isEquals("check direct reference", null, dle.getDirectReference());
        isTrue("check existence of indirect reference", dle.getIndirectReference() != null);
        isEquals("check indirect reference", "9", dle.getIndirectReference().getValue().toString());
        isTrue("check existence of data value descriptor", dle.getDataValueDescriptor() != null);
        dvdType = dle.getDataValueDescriptor().getClass().getName();
        isEquals("check type of value descriptor: " + dvdType, DERUTF8String.class.getName(), dvdType);
        isEquals("check value", "something completely different", ((ASN1UTF8String)dle.getDataValueDescriptor()).getString());
        isEquals("check encoding", 0, dle.getEncoding());
        isTrue("check existence of external content", dle.getExternalContent() != null);
        ecType = dle.getExternalContent().getClass().getName();
        isEquals("check type of external content: " + ecType, ASN1Integer.class.getName(), ecType);
        isEquals("check value of external content", "1234567890", ((ASN1Integer)dle.getExternalContent()).getValue().toString());

        dle = new DLExternal(createRealDataExample(0));
        checkRealDataExample(0, dle);

        dle = new DLExternal(createRealDataExample(1));
        checkRealDataExample(1, dle);

        dle = new DLExternal(createRealDataExample(2));
        checkRealDataExample(2, dle);
    }

    /**
     * Checks that a DLExternal is created from DER encoded bytes correctly.
     * This is done by creating the DER encoded data by using <code>getEncoded</code>
     *
     * @throws Exception Will be thrown if there was an
     *                   error while performing the test
     */
    public void testReadEncoded()
        throws Exception
    {
        implTestReadEncoded(0);
        implTestReadEncoded(1);
        implTestReadEncoded(2);
    }

    private void checkRealDataExample(int encoding, DLExternal dle)
        throws IOException
    {
        //System.out.println(ASN1Dump.dumpAsString(dle, true));
        isEquals("check direct reference", "2.1.1", String.valueOf(dle.getDirectReference()));
        isEquals("check indirect reference", "9", String.valueOf(dle.getIndirectReference()));
        isEquals("check data value decriptor", "example data representing the User Data of an OSI.6 ConnectP containing an MSBind with username and password", String.valueOf(dle.getDataValueDescriptor()));
        isEquals("check encoding", encoding, dle.getEncoding());

        ASN1Primitive content = dle.getExternalContent();
        isTrue("check existence of content", content != null);

        ASN1TaggedObject msBind;
        switch (encoding)
        {
        case 1:
            isTrue("check type is an OCTET STRING: " + content.getClass(), content instanceof ASN1OctetString);
            ASN1OctetString octetString = (ASN1OctetString)content;
            msBind = ASN1TaggedObject.getInstance(octetString.getOctets());
            break;
        case 2:
            isTrue("check type is a BIT STRING: " + content.getClass(), content instanceof ASN1BitString);
            ASN1BitString bitString = (ASN1BitString)content;
            msBind = ASN1TaggedObject.getInstance(bitString.getBytes());
            break;
        default:
            isTrue("check type is a tagged object: " + content.getClass(), content instanceof ASN1TaggedObject);
            msBind = (ASN1TaggedObject)content;
            break;
        }

        isTrue("check tag", msBind.hasContextTag(16));
        isEquals("check explicit", true, msBind.isExplicit());
        isEquals("check tagged object is a DLSet: " + msBind.getBaseUniversal(true, BERTags.SET).getClass(),
            DLSet.class.getName(), msBind.getBaseUniversal(true, BERTags.SET).getClass().getName());

        DLSet msBindSet = (DLSet)msBind.getBaseUniversal(true, BERTags.SET);
        isEquals("check number of elements", 2, msBindSet.size());
        isEquals("check first element in set: " + msBindSet.getObjectAt(0).getClass(), DLTaggedObject.class.getName(), msBindSet.getObjectAt(0).getClass().getName());

        DLTaggedObject objectName = (DLTaggedObject)msBindSet.getObjectAt(0);
        isEquals("check tag number", true, objectName.hasTag(BERTags.APPLICATION, 0));
        isEquals("check application object: " + objectName.getBaseObject().toASN1Primitive().getClass(), DLSequence.class.getName(), objectName.getBaseObject().toASN1Primitive().getClass().getName());
        DLSequence objNameElems = (DLSequence)objectName.getBaseObject().toASN1Primitive();
        isEquals("check number of elements", 4, objNameElems.size());
        isEquals("check first element in set: " + objNameElems.getObjectAt(0).getClass(), DLTaggedObject.class.getName(), objNameElems.getObjectAt(0).getClass().getName());
        DLTaggedObject objNameAppl = (DLTaggedObject)objNameElems.getObjectAt(0);
        isEquals("check application number", true, objNameAppl.hasTag(BERTags.APPLICATION, 0));
        isEquals("check application object: " + objNameAppl.getBaseObject().toASN1Primitive().getClass(), DERPrintableString.class.getName(), objNameAppl.getBaseObject().toASN1Primitive().getClass().getName());
        isEquals("check C", "de", ((DERPrintableString)objNameAppl.getBaseObject().toASN1Primitive()).getString());
        isEquals("check second element in set: " + objNameElems.getObjectAt(1).getClass(), DLTaggedObject.class.getName(), objNameElems.getObjectAt(1).getClass().getName());
        objNameAppl = (DLTaggedObject)objNameElems.getObjectAt(1);
        isEquals("check application number", true, objNameAppl.hasTag(BERTags.APPLICATION, 2));
        isEquals("check application object: " + objNameAppl.getBaseObject().toASN1Primitive().getClass(), DERPrintableString.class.getName(), objNameAppl.getBaseObject().toASN1Primitive().getClass().getName());
        isEquals("check A", "viaT", ((DERPrintableString)objNameAppl.getBaseObject().toASN1Primitive()).getString());
        isEquals("check third element in set: " + objNameElems.getObjectAt(2).getClass(), DLTaggedObject.class.getName(), objNameElems.getObjectAt(2).getClass().getName());
        DLTaggedObject objNameTagged = (DLTaggedObject)objNameElems.getObjectAt(2);
        isTrue("check tag", objNameTagged.hasContextTag(3));
        isEquals("check implicit", false, objNameTagged.isExplicit());
        isEquals("check tagged object: " + objNameTagged.getBaseUniversal(false, BERTags.OCTET_STRING).getClass(), DEROctetString.class.getName(), objNameTagged.getBaseUniversal(false, BERTags.OCTET_STRING).getClass().getName());
        isEquals("check O", "Organization", new String(((DEROctetString)objNameTagged.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets(), "8859_1"));
        isEquals("check fourth element in set: " + objNameElems.getObjectAt(3).getClass(), DLTaggedObject.class.getName(), objNameElems.getObjectAt(3).getClass().getName());
        objNameTagged = (DLTaggedObject)objNameElems.getObjectAt(3);
        isTrue("check tag", objNameTagged.hasContextTag(5));
        isEquals("check explicit", true, objNameTagged.isExplicit());
        isEquals("check tagged object: " + objNameTagged.getExplicitBaseTagged().getClass(), DLTaggedObject.class.getName(), objNameTagged.getExplicitBaseTagged().getClass().getName());
        objNameTagged = (DLTaggedObject)objNameTagged.getExplicitBaseTagged();
        isTrue("check tag", objNameTagged.hasContextTag(0));
        isEquals("check implicit", false, objNameTagged.isExplicit());
        isEquals("check tagged object: " + objNameTagged.getBaseUniversal(false, BERTags.OCTET_STRING).getClass(), DEROctetString.class.getName(), objNameTagged.getBaseUniversal(false, BERTags.OCTET_STRING).getClass().getName());
        isEquals("check CN", "Common Name", new String(((DEROctetString)objNameTagged.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets(), "8859_1"));

        isEquals("check second element in set: " + msBindSet.getObjectAt(1).getClass(), DLTaggedObject.class.getName(), msBindSet.getObjectAt(1).getClass().getName());
        DLTaggedObject password = (DLTaggedObject)msBindSet.getObjectAt(1);
        isTrue("check tag", password.hasContextTag(2));
        isEquals("check explicit", true, password.isExplicit());
        isEquals("check tagged object: " + password.getBaseUniversal(true, BERTags.IA5_STRING).getClass(), DERIA5String.class.getName(), password.getBaseUniversal(true, BERTags.IA5_STRING).getClass().getName());
        isEquals("check password", "SomePassword", ((ASN1IA5String)password.getBaseUniversal(true, BERTags.IA5_STRING)).getString());
    }

    private ASN1EncodableVector createRealDataExample(int encoding)
        throws IOException
    {
        ASN1EncodableVector vec = new ASN1EncodableVector();

        vec.add(new ASN1ObjectIdentifier("2.1.1"));
        vec.add(new ASN1Integer(9));
        vec.add(new DERUTF8String("example data representing the User Data of an OSI.6 ConnectP containing an MSBind with username and password"));

        ASN1EncodableVector objectNameVec = new ASN1EncodableVector();
        objectNameVec.add(new DLTaggedObject(BERTags.APPLICATION, 0, new DERPrintableString("de")));
        objectNameVec.add(new DLTaggedObject(BERTags.APPLICATION, 2, new DERPrintableString("viaT")));
        objectNameVec.add(new DLTaggedObject(false, 3, new DEROctetString("Organization".getBytes("8859_1"))));
        objectNameVec.add(new DLTaggedObject(true, 5, new DLTaggedObject(false, 0, new DEROctetString("Common Name".getBytes("8859_1")))));

        DLTaggedObject objectName = new DLTaggedObject(BERTags.APPLICATION, 0, new DLSequence(objectNameVec));
        DLTaggedObject password = new DLTaggedObject(true, 2, new DERIA5String("SomePassword"));
        ASN1EncodableVector msBindVec = new ASN1EncodableVector();
        msBindVec.add(objectName);
        msBindVec.add(password);
        DLSet msBindSet = new DLSet(msBindVec);
        DLTaggedObject msBind = new DLTaggedObject(true, 16, msBindSet);

        ASN1Primitive obj = msBind;
        switch (encoding)
        {
        case 1:
        {
            obj = new DEROctetString(obj.getEncoded(ASN1Encoding.DL));
            break;
        }
        case 2:
        {
            obj = new DLBitString(obj.getEncoded(ASN1Encoding.DL));
            break;
        }
        }

        vec.add(new DLTaggedObject(0 == encoding, encoding, obj));
        return vec;
    }

    private void implTestReadEncoded(int encoding) throws Exception
    {
        DLExternal dle = new DLExternal(createRealDataExample(encoding));

        ASN1InputStream ais = new ASN1InputStream(dle.getEncoded());
        ASN1Primitive ap = ais.readObject();
        isTrue("check ais returned an object", ap != null);
        isEquals("check returned type: " + ap.getClass(), DLExternal.class.getName(), ap.getClass().getName());
        checkRealDataExample(encoding, (DLExternal)ap);
        ais.close();
    }

    public String getName()
    {
        return "DLExternal";
    }

    public void performTest()
        throws Exception
    {
        testInstantiationByVector();
        testReadEncoded();
    }

    /**
     * Main method to start testing manually outside production
     *
     * @param args Calling arguments (not used here)
     */
    public static void main(String[] args)
    {
        runTest(new DLExternalTest());
    }
}
