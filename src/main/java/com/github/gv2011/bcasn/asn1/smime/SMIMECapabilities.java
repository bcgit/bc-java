package com.github.gv2011.bcasn.asn1.smime;

import java.util.Enumeration;
import java.util.Vector;

import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.cms.Attribute;
import com.github.gv2011.bcasn.asn1.nist.NISTObjectIdentifiers;
import com.github.gv2011.bcasn.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Handler class for dealing with S/MIME Capabilities
 */
public class SMIMECapabilities
    extends ASN1Object
{
    /**
     * general preferences
     */
    public static final ASN1ObjectIdentifier preferSignedData = PKCSObjectIdentifiers.preferSignedData;
    public static final ASN1ObjectIdentifier canNotDecryptAny = PKCSObjectIdentifiers.canNotDecryptAny;
    public static final ASN1ObjectIdentifier sMIMECapabilitesVersions = PKCSObjectIdentifiers.sMIMECapabilitiesVersions;

    /**
     * encryption algorithms preferences
     */
    public static final ASN1ObjectIdentifier aes256_CBC = NISTObjectIdentifiers.id_aes256_CBC;
    public static final ASN1ObjectIdentifier aes192_CBC = NISTObjectIdentifiers.id_aes192_CBC;
    public static final ASN1ObjectIdentifier aes128_CBC = NISTObjectIdentifiers.id_aes128_CBC;
    public static final ASN1ObjectIdentifier idea_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");
    public static final ASN1ObjectIdentifier cast5_CBC = new ASN1ObjectIdentifier("1.2.840.113533.7.66.10");
    public static final ASN1ObjectIdentifier dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
    public static final ASN1ObjectIdentifier dES_EDE3_CBC = PKCSObjectIdentifiers.des_EDE3_CBC;
    public static final ASN1ObjectIdentifier rC2_CBC = PKCSObjectIdentifiers.RC2_CBC;
    
    private ASN1Sequence         capabilities;

    /**
     * return an Attribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static SMIMECapabilities getInstance(
        Object o)
    {
        if (o == null || o instanceof SMIMECapabilities)
        {
            return (SMIMECapabilities)o;
        }
        
        if (o instanceof ASN1Sequence)
        {
            return new SMIMECapabilities((ASN1Sequence)o);
        }

        if (o instanceof Attribute)
        {
            return new SMIMECapabilities(
                (ASN1Sequence)(((Attribute)o).getAttrValues().getObjectAt(0)));
        }

        throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
    }
    
    public SMIMECapabilities(
        ASN1Sequence seq)
    {
        capabilities = seq;
    }

    /**
     * returns a vector with 0 or more objects of all the capabilities
     * matching the passed in capability OID. If the OID passed is null the
     * entire set is returned.
     */
    public Vector getCapabilities(
        ASN1ObjectIdentifier capability)
    {
        Enumeration e = capabilities.getObjects();
        Vector      list = new Vector();

        if (capability == null)
        {
            while (e.hasMoreElements())
            {
                SMIMECapability  cap = SMIMECapability.getInstance(e.nextElement());

                list.addElement(cap);
            }
        }
        else
        {
            while (e.hasMoreElements())
            {
                SMIMECapability  cap = SMIMECapability.getInstance(e.nextElement());

                if (capability.equals(cap.getCapabilityID()))
                {
                    list.addElement(cap);
                }
            }
        }

        return list;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * SMIMECapabilities ::= SEQUENCE OF SMIMECapability
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return capabilities;
    }
}
