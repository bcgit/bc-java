package org.bouncycastle.asn1.x500;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * A builder class for making X.500 Name objects.
 */
public class X500NameBuilder
{
    private X500NameStyle template;
    private Vector rdns = new Vector();

    /**
     * Constructor using the default style (BCStyle).
     */
    public X500NameBuilder()
    {
        this(BCStyle.INSTANCE);
    }

    /**
     * Constructor using a specified style.
     *
     * @param template the style template for string to DN conversion.
     */
    public X500NameBuilder(X500NameStyle template)
    {
        this.template = template;
    }

    /**
     * Add an RDN based on a single OID and a string representation of its value.
     *
     * @param oid the OID for this RDN.
     * @param value the string representation of the value the OID refers to.
     * @return the current builder instance.
     */
    public X500NameBuilder addRDN(ASN1ObjectIdentifier oid, String value)
    {
        this.addRDN(oid, template.stringToValue(oid, value));

        return this;
    }

    /**
     * Add an RDN based on a single OID and an ASN.1 value.
     *
     * @param oid the OID for this RDN.
     * @param value the ASN.1 value the OID refers to.
     * @return the current builder instance.
     */
    public X500NameBuilder addRDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
    {
        rdns.addElement(new RDN(oid, value));

        return this;
    }

    /**
     * Add an RDN based on the passed in AttributeTypeAndValue.
     *
     * @param attrTAndV the AttributeTypeAndValue to build the RDN from.
     * @return the current builder instance.
     */
    public X500NameBuilder addRDN(AttributeTypeAndValue attrTAndV)
    {
        rdns.addElement(new RDN(attrTAndV));

        return this;
    }

    /**
     * Add a multi-valued RDN made up of the passed in OIDs and associated string values.
     *
     * @param oids the OIDs making up the RDN.
     * @param values the string representation of the values the OIDs refer to.
     * @return the current builder instance.
     */
    public X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, String[] values)
    {
        ASN1Encodable[] vals = new ASN1Encodable[values.length];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = template.stringToValue(oids[i], values[i]);
        }

        return addMultiValuedRDN(oids, vals);
    }

    /**
     * Add a multi-valued RDN made up of the passed in OIDs and associated ASN.1 values.
     *
     * @param oids the OIDs making up the RDN.
     * @param values the ASN.1 values the OIDs refer to.
     * @return the current builder instance.
     */
    public X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, ASN1Encodable[] values)
    {
        AttributeTypeAndValue[] avs = new AttributeTypeAndValue[oids.length];

        for (int i = 0; i != oids.length; i++)
        {
            avs[i] = new AttributeTypeAndValue(oids[i], values[i]);
        }

        return addMultiValuedRDN(avs);
    }

    /**
     * Add an RDN based on the passed in AttributeTypeAndValues.
     *
     * @param attrTAndVs the AttributeTypeAndValues to build the RDN from.
     * @return the current builder instance.
     */
    public X500NameBuilder addMultiValuedRDN(AttributeTypeAndValue[] attrTAndVs)
    {
        rdns.addElement(new RDN(attrTAndVs));

        return this;
    }

    /**
     * Build an X.500 name for the current builder state.
     *
     * @return a new X.500 name.
     */
    public X500Name build()
    {
        RDN[] vals = new RDN[rdns.size()];

        for (int i = 0; i != vals.length; i++)
        {
            vals[i] = (RDN)rdns.elementAt(i);
        }

        return new X500Name(template, vals);
    }
}