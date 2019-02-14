package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;

/**
 * Generator for X.509 extensions
 */
public class ExtensionsGenerator
{
    private Hashtable extensions = new Hashtable();
    private Vector extOrdering = new Vector();

    /**
     * Reset the generator
     */
    public void reset()
    {
        extensions = new Hashtable();
        extOrdering = new Vector();
    }

    /**
     * Add an extension with the given oid and the passed in value to be included
     * in the OCTET STRING associated with the extension.
     *
     * @param oid  OID for the extension.
     * @param critical  true if critical, false otherwise.
     * @param value the ASN.1 object to be included in the extension.
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        ASN1Encodable        value)
        throws IOException
    {
        this.addExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    /**
     * Add an extension with the given oid and the passed in byte array to be wrapped in the
     * OCTET STRING associated with the extension.
     *
     * @param oid OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value the byte array to be wrapped.
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean             critical,
        byte[]              value)
    {
        if (extensions.containsKey(oid))
        {
            throw new IllegalArgumentException("extension " + oid + " already added");
        }

        extOrdering.addElement(oid);
        extensions.put(oid, new Extension(oid, critical, new DEROctetString(value)));
    }

    /**
     * Add a given extension.
     *
     * @param extension the full extension value.
     */
    public void addExtension(
        Extension extension)
    {
        if (extensions.containsKey(extension.getExtnId()))
        {
            throw new IllegalArgumentException("extension " + extension.getExtnId() + " already added");
        }

        extOrdering.addElement(extension.getExtnId());
        extensions.put(extension.getExtnId(), extension);
    }

    /**
     * Replace an extension with the given oid and the passed in value to be included
     * in the OCTET STRING associated with the extension.
     *
     * @param oid  OID for the extension.
     * @param critical  true if critical, false otherwise.
     * @param value the ASN.1 object to be included in the extension.
     */
    public void replaceExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        ASN1Encodable        value)
        throws IOException
    {
        this.replaceExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    /**
     * Replace an extension with the given oid and the passed in byte array to be wrapped in the
     * OCTET STRING associated with the extension.
     *
     * @param oid OID for the extension.
     * @param critical true if critical, false otherwise.
     * @param value the byte array to be wrapped.
     */
    public void replaceExtension(
        ASN1ObjectIdentifier oid,
        boolean             critical,
        byte[]              value)
    {
        this.replaceExtension(new Extension(oid, critical, value));
    }

    /**
     * Replace a given extension.
     *
     * @param extension the full extension value.
     */
    public void replaceExtension(
        Extension extension)
    {
        if (!extensions.containsKey(extension.getExtnId()))
        {
            throw new IllegalArgumentException("extension " + extension.getExtnId() + " not present");
        }

        extensions.put(extension.getExtnId(), extension);
    }

    /**
     * Remove a given extension.
     *
     * @param oid OID for the extension to remove.
     */
    public void removeExtension(
        ASN1ObjectIdentifier oid)
    {
        if (!extensions.containsKey(oid))
        {
            throw new IllegalArgumentException("extension " + oid + " not present");
        }

        extOrdering.removeElement(oid);
        extensions.remove(oid);
    }

    /**
     * Return if the extension indicated by OID is present.
     *
     * @param oid the OID for the extension of interest.
     * @return the Extension, or null if it is not present.
     */
    public boolean hasExtension(ASN1ObjectIdentifier oid)
    {
         return extensions.containsKey(oid);
    }

    /**
     * Return the current value of the extension for OID.
     *
     * @param oid the OID for the extension we want to fetch.
     * @return true if a matching extension is present, false otherwise.
     */
    public Extension getExtension(ASN1ObjectIdentifier oid)
    {
         return (Extension)extensions.get(oid);
    }

    /**
     * Return true if there are no extension present in this generator.
     *
     * @return true if empty, false otherwise
     */
    public boolean isEmpty()
    {
        return extOrdering.isEmpty();
    }

    /**
     * Generate an Extensions object based on the current state of the generator.
     *
     * @return  an X09Extensions object.
     */
    public Extensions generate()
    {
        Extension[] exts = new Extension[extOrdering.size()];

        for (int i = 0; i != extOrdering.size(); i++)
        {
            exts[i] = (Extension)extensions.get(extOrdering.elementAt(i));
        }

        return new Extensions(exts);
    }
}
