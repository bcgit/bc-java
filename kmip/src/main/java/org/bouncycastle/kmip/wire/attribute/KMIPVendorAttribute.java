package org.bouncycastle.kmip.wire.attribute;


/**
 * Represents a vendor-specific attribute used for sending and receiving Managed Object attributes.
 * Vendor Identification and Attribute Name are text strings used to identify the attribute, while Attribute Value
 * varies depending on the specific attribute.
 * <p>
 * Vendor Attributes created by the client with Vendor Identification “x” are not created (provided during
 * object creation), set, added, adjusted, modified or deleted by the server.
 * <p>
 * Vendor Attributes created by the server with Vendor Identification “y” are not created (provided during
 * object creation), set, added, adjusted, modified or deleted by the client.
 */
public class KMIPVendorAttribute
{

    // Vendor identification (alphanumeric, underscore, and period allowed).
    private String vendorIdentification;

    // Attribute name (text string).
    private String attributeName;

    // Attribute value can vary depending on the attribute type (could be primitive or structured).
    private Object attributeValue;

    /**
     * Constructor for VendorAttribute.
     *
     * @param vendorIdentification The vendor identification value.
     * @param attributeName        The attribute name.
     * @param attributeValue       The attribute value (could vary in type).
     */
    public KMIPVendorAttribute(String vendorIdentification, String attributeName, Object attributeValue)
    {
        this.vendorIdentification = vendorIdentification;
        this.attributeName = attributeName;
        this.attributeValue = attributeValue;
    }

    // Getters and Setters

    public String getVendorIdentification()
    {
        return vendorIdentification;
    }

    public void setVendorIdentification(String vendorIdentification)
    {
        this.vendorIdentification = vendorIdentification;
    }

    public String getAttributeName()
    {
        return attributeName;
    }

    public void setAttributeName(String attributeName)
    {
        this.attributeName = attributeName;
    }

    public Object getAttributeValue()
    {
        return attributeValue;
    }

    public void setAttributeValue(Object attributeValue)
    {
        this.attributeValue = attributeValue;
    }
}
