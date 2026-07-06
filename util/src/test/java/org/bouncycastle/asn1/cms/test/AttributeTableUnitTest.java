package org.bouncycastle.asn1.cms.test;

import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.util.test.SimpleTest;

public class AttributeTableUnitTest 
    extends SimpleTest
{
    private static final ASN1ObjectIdentifier type1 = new ASN1ObjectIdentifier("1.1.1");
    private static final ASN1ObjectIdentifier type2 = new ASN1ObjectIdentifier("1.1.2");
    private static final ASN1ObjectIdentifier type3 = new ASN1ObjectIdentifier("1.1.3");
    
    public String getName()
    {
        return "AttributeTable";
    }
    
    public void performTest() 
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(new Attribute(type1, new DERSet(type1)));
        v.add(new Attribute(type2, new DERSet(type2)));
        
        AttributeTable table = new AttributeTable(v);
        
        Attribute a = table.get(type1);
        if (a == null)
        {
            fail("type1 attribute not found.");
        }
        if (!a.getAttrValues().equals(new DERSet(type1)))
        {
            fail("wrong value retrieved for type1!");
        }
        
        a = table.get(type2);
        if (a == null)
        {
            fail("type2 attribute not found.");
        }
        if (!a.getAttrValues().equals(new DERSet(type2)))
        {
            fail("wrong value retrieved for type2!");
        }
        
        a = table.get(type3);
        if (a != null)
        {
            fail("type3 attribute found when none expected.");
        }

        isTrue(table.hasAny(type1));

        ASN1EncodableVector vec = table.getAll(type1);
        if (vec.size() != 1)
        {
            fail("wrong vector size for type1.");
        }

        isTrue(!table.hasAny(type3));

        vec = table.getAll(type3);
        if (vec.size() != 0)
        {
            fail("wrong vector size for type3.");
        }
        
        vec = table.toASN1EncodableVector();
        if (vec.size() != 2)
        {
            fail("wrong vector size for single.");
        }
        
        Hashtable t = table.toHashtable();
        
        if (t.size() != 2)
        {
            fail("hashtable wrong size.");
        }
        
        // multiple
        
        v = new ASN1EncodableVector();
        
        v.add(new Attribute(type1, new DERSet(type1)));
        v.add(new Attribute(type1, new DERSet(type2)));
        v.add(new Attribute(type1, new DERSet(type3)));
        v.add(new Attribute(type2, new DERSet(type2)));
        
        table = new AttributeTable(v);
        
        a = table.get(type1);
        if (!a.getAttrValues().equals(new DERSet(type1)))
        {
            fail("wrong value retrieved for type1 multi get!");
        }

        isTrue(table.hasAny(type1));

        vec = table.getAll(type1);
        if (vec.size() != 3)
        {
            fail("wrong vector size for multiple type1.");
        }
        
        a = (Attribute)vec.get(0);
        if (!a.getAttrValues().equals(new DERSet(type1)))
        {
            fail("wrong value retrieved for type1(0)!");
        }
        
        a = (Attribute)vec.get(1);
        if (!a.getAttrValues().equals(new DERSet(type2)))
        {
            fail("wrong value retrieved for type1(1)!");
        }
        
        a = (Attribute)vec.get(2);
        if (!a.getAttrValues().equals(new DERSet(type3)))
        {
            fail("wrong value retrieved for type1(2)!");
        }

        isTrue(table.hasAny(type2));

        vec = table.getAll(type2);
        if (vec.size() != 1)
        {
            fail("wrong vector size for multiple type2.");
        }
        
        vec = table.toASN1EncodableVector();
        if (vec.size() != 4)
        {
            fail("wrong vector size for multiple.");
        }

        // Attribute.getInstance must reject a structurally-valid SEQUENCE whose type element is not an
        // OBJECT IDENTIFIER (here a tagged object) with IllegalArgumentException, rather than leak a
        // ClassCastException from the (ASN1ObjectIdentifier) cast out of the getInstance contract.
        ASN1EncodableVector badAttr = new ASN1EncodableVector();
        badAttr.add(new DERTaggedObject(0, new DEROctetString(new byte[]{ 1, 2, 3 })));
        badAttr.add(new DERSet());
        try
        {
            Attribute.getInstance(new DERSequence(badAttr));
            fail("Attribute.getInstance accepted a non-OID type element");
        }
        catch (IllegalArgumentException e)
        {
            // expected - documented malformed reject
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new AttributeTableUnitTest());
    }
}
