package org.bouncycastle.cms.test;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSAttributeTableGenerator;

/**
 * An attribute table generator that keeps a copy of the parameters it was last given and returns one fixed
 * attribute, so a test can check what a CMS generator hands its attribute generators.
 */
class RecordingAttributeTableGenerator
    implements CMSAttributeTableGenerator
{
    static final ASN1ObjectIdentifier ATTR_TYPE = new ASN1ObjectIdentifier("1.2.3.4.5");

    private Map parameters;
    private int calls;

    public AttributeTable getAttributes(Map parameters)
    {
        this.parameters = new HashMap(parameters);
        this.calls++;

        return new AttributeTable(new Attribute(ATTR_TYPE, new DERSet(new DERUTF8String("recorded"))));
    }

    Map getParameters()
    {
        return parameters;
    }

    int getCalls()
    {
        return calls;
    }
}
