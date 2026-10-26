package org.bouncycastle.asn1.cms.test;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
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

        derivedTableTest();
        collidingTypeTest();
    }

    private void derivedTableTest()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new Attribute(type1, new DERSet(type1)));
        v.add(new Attribute(type1, new DERSet(type2)));
        AttributeTable base = new AttributeTable(v);

        AttributeTable derived = base.add(type1, type3);
        if (derived.getAll(type1).size() != 3)
        {
            fail("derived table should hold the added attribute");
        }
        if (base.getAll(type1).size() != 2)
        {
            fail("add() must not grow the table it was derived from");
        }
        if (base.remove(type1).size() != 0 || base.size() != 2)
        {
            fail("remove() must not touch the table it was derived from");
        }

        Hashtable copy = base.toHashtable();
        if (copy.size() != 1 || !(copy.get(type1) instanceof java.util.Vector))
        {
            fail("toHashtable() should key a repeated type on its OID with a Vector of the values");
        }
        if (new AttributeTable(copy).getAll(type1).size() != 2)
        {
            fail("Hashtable round trip lost attributes");
        }
    }

    /**
     * The table is built from a message's attributes before anything is verified, so a block of
     * attribute types sharing one hash code must still index in linear time.
     */
    private void collidingTypeTest()
        throws Exception
    {
        ASN1ObjectIdentifier[] oids = collidingOIDs(15);
        int n = oids.length;
        for (int i = 1; i != n; i++)
        {
            isTrue("hash codes should coincide", oids[0].hashCode() == oids[i].hashCode());
        }

        ASN1EncodableVector attrs = new ASN1EncodableVector(n);
        for (int i = 0; i != n; i++)
        {
            attrs.add(new Attribute(oids[i], new DERSet(DERNull.INSTANCE)));
        }
        ASN1Set attrSet = ASN1Set.getInstance(new DLSet(attrs).getEncoded());

        long start = System.currentTimeMillis();
        AttributeTable table = new AttributeTable(attrSet);
        long elapsed = System.currentTimeMillis() - start;

        isTrue("attribute count", table.size() == n);
        isTrue("last attribute lookup", table.get(oids[n - 1]) != null);
        isTrue("absent attribute lookup", !table.hasAny(type1));
        isTrue("colliding types took " + elapsed + "ms", elapsed < 3000L);
    }

    /**
     * 2^log2n distinct OIDs under 1.3 whose ASN1ObjectIdentifier.hashCode() values coincide. The hash is
     * a 257-multiplier fold over the content octets from the last to the first, so starting from a common
     * tail each five-octet component position allows a birthday search for two encodings that leave the
     * fold in the same state, after which every choice at every position gives the same hash.
     */
    private static ASN1ObjectIdentifier[] collidingOIDs(int log2n)
    {
        byte[] tail = { 0x06, 0x01, 0x04, 0x01, 0x7F };
        int length = 1 + 5 * log2n + tail.length;
        int state = foldHash(length + 1, tail);
        byte[][][] pairs = new byte[log2n][][];
        Random rnd = new Random(1);

        for (int i = 0; i < log2n; i++)
        {
            pairs[i] = collidingPair(state, rnd);
            state = foldHash(state, pairs[i][0]);
        }

        ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[1 << log2n];
        for (int x = 0; x < oids.length; x++)
        {
            byte[] enc = new byte[2 + length];
            enc[0] = 0x06;
            enc[1] = (byte)length;
            enc[2] = 0x2B;
            int p = 3;
            for (int i = log2n - 1; i >= 0; i--)
            {
                System.arraycopy(pairs[i][(x >> i) & 1], 0, enc, p, 5);
                p += 5;
            }
            System.arraycopy(tail, 0, enc, p, tail.length);
            oids[x] = ASN1ObjectIdentifier.getInstance(enc);
        }

        return oids;
    }

    private static int foldHash(int state, byte[] block)
    {
        for (int i = block.length - 1; i >= 0; i--)
        {
            state *= 257;
            state ^= block[i];
        }
        return state;
    }

    private static byte[][] collidingPair(int state, Random rnd)
    {
        Map seen = new HashMap();
        for (;;)
        {
            byte[] b = { (byte)(0x80 | (1 + rnd.nextInt(127))), (byte)(0x80 | rnd.nextInt(128)),
                (byte)(0x80 | rnd.nextInt(128)), (byte)(0x80 | rnd.nextInt(128)), (byte)rnd.nextInt(128) };
            Integer out = Integers.valueOf(foldHash(state, b));
            byte[] prev = (byte[])seen.get(out);
            if (prev != null && !Arrays.areEqual(prev, b))
            {
                return new byte[][]{ prev, b };
            }
            seen.put(out, b);
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new AttributeTableUnitTest());
    }
}
