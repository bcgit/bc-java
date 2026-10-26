package org.bouncycastle.asn1.cms;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;

/**
 * This is helper tool to construct {@link Attributes} sets.
 */
public class AttributeTable
{
    // keyed on the attribute type's string form, each value an Attribute or a Vector of them: an ordered
    // map keeps a block of attributes whose types share a hash code linear to index
    private Map attributes = new TreeMap();

    public AttributeTable(
        Hashtable  attrs)
    {
        Enumeration e = attrs.keys();

        while (e.hasMoreElements())
        {
            Object key = e.nextElement();

            putValue(ASN1ObjectIdentifier.getInstance(key).getId(), attrs.get(key));
        }
    }

    public AttributeTable(
        ASN1EncodableVector v)
    {
        for (int i = 0; i != v.size(); i++)
        {
            Attribute   a = Attribute.getInstance(v.get(i));

            addAttribute(a.getAttrType(), a);
        }
    }

    public AttributeTable(
        ASN1Set    s)
    {
        for (int i = 0; i != s.size(); i++)
        {
            Attribute   a = Attribute.getInstance(s.getObjectAt(i));

            addAttribute(a.getAttrType(), a);
        }
    }

    public AttributeTable(
        Attribute    attr)
    {
        addAttribute(attr.getAttrType(), attr);
    }

    public AttributeTable(
        Attributes    attrs)
    {
        this(ASN1Set.getInstance(attrs.toASN1Primitive()));
    }

    private AttributeTable(
        AttributeTable other)
    {
        for (Iterator it = other.attributes.keySet().iterator(); it.hasNext();)
        {
            Object key = it.next();

            putValue((String)key, other.attributes.get(key));
        }
    }

    private void putValue(String key, Object value)
    {
        // a Vector is copied so that a table derived by add() or remove() cannot grow its source
        attributes.put(key, value instanceof Vector ? new Vector((Vector)value) : value);
    }

    private void addAttribute(
        ASN1ObjectIdentifier oid,
        Attribute           a)
    {
        String key = oid.getId();
        Object value = attributes.get(key);

        if (value == null)
        {
            attributes.put(key, a);
        }
        else
        {
            Vector v;

            if (value instanceof Attribute)
            {
                v = new Vector();

                v.addElement(value);
                v.addElement(a);
            }
            else
            {
                v = (Vector)value;

                v.addElement(a);
            }

            attributes.put(key, v);
        }
    }

    /**
     * Return the first attribute matching the OBJECT IDENTIFIER oid.
     *
     * @param oid type of attribute required.
     * @return first attribute found of type oid.
     */
    public Attribute get(
        ASN1ObjectIdentifier oid)
    {
        Object value = attributes.get(oid.getId());

        if (value instanceof Vector)
        {
            return (Attribute)((Vector)value).elementAt(0);
        }

        return (Attribute)value;
    }

    /**
     * Return all the attributes matching the OBJECT IDENTIFIER oid. The vector will be
     * empty if there are no attributes of the required type present.
     *
     * @param oid type of attribute required.
     * @return a vector of all the attributes found of type oid.
     */
    public ASN1EncodableVector getAll(
        ASN1ObjectIdentifier oid)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        Object value = attributes.get(oid.getId());

        if (value instanceof Vector)
        {
            Enumeration e = ((Vector)value).elements();

            while (e.hasMoreElements())
            {
                v.add((Attribute)e.nextElement());
            }
        }
        else if (value != null)
        {
            v.add((Attribute)value);
        }

        return v;
    }

    public boolean hasAny(ASN1ObjectIdentifier oid)
    {
        return attributes.containsKey(oid.getId());
    }

    public int size()
    {
        int size = 0;

        for (Iterator it = attributes.values().iterator(); it.hasNext();)
        {
            Object o = it.next();

            if (o instanceof Vector)
            {
                size += ((Vector)o).size();
            }
            else
            {
                size++;
            }
        }

        return size;
    }

    /**
     * Return the table's contents as a Hashtable keyed on attribute type, each value an Attribute
     * or, for a type present more than once, a Vector of them.
     *
     * @return a copy of the table's contents.
     */
    public Hashtable toHashtable()
    {
        Hashtable out = new Hashtable();

        for (Iterator it = attributes.values().iterator(); it.hasNext();)
        {
            Object value = it.next();
            Attribute first = (value instanceof Vector) ? (Attribute)((Vector)value).elementAt(0) : (Attribute)value;

            out.put(first.getAttrType(), value instanceof Vector ? new Vector((Vector)value) : value);
        }

        return out;
    }

    public ASN1EncodableVector toASN1EncodableVector()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        for (Iterator it = attributes.values().iterator(); it.hasNext();)
        {
            Object value = it.next();

            if (value instanceof Vector)
            {
                Enumeration en = ((Vector)value).elements();

                while (en.hasMoreElements())
                {
                    v.add(Attribute.getInstance(en.nextElement()));
                }
            }
            else
            {
                v.add(Attribute.getInstance(value));
            }
        }

        return v;
    }

    public Attributes toASN1Structure()
    {
        return new Attributes(this.toASN1EncodableVector());
    }

    /**
     * Return a new table with the passed in attribute added.
     *
     * @param attrType the type of the attribute to add.
     * @param attrValue the value corresponding to the attribute (will be wrapped in a SET).
     * @return a new table with the extra attribute in it.
     */
    public AttributeTable add(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        AttributeTable newTable = new AttributeTable(this);

        newTable.addAttribute(attrType, new Attribute(attrType, new DERSet(attrValue)));

        return newTable;
    }

    public AttributeTable remove(ASN1ObjectIdentifier attrType)
    {
        AttributeTable newTable = new AttributeTable(this);

        newTable.attributes.remove(attrType.getId());

        return newTable;
    }
}
