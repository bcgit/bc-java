package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * The extendedKeyUsage object.
 * <pre>
 *      extendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * </pre>
 */
public class ExtendedKeyUsage
    extends ASN1Object
{
    Hashtable     usageTable = new Hashtable();
    ASN1Sequence  seq;

    public static ExtendedKeyUsage getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ExtendedKeyUsage getInstance(
        Object obj)
    {
        if (obj instanceof ExtendedKeyUsage) 
        {
            return (ExtendedKeyUsage)obj;
        }
        else if (obj != null)
        {
            return new ExtendedKeyUsage(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ExtendedKeyUsage fromExtensions(Extensions extensions)
    {
        return ExtendedKeyUsage.getInstance(extensions.getExtensionParsedValue(Extension.extendedKeyUsage));
    }

    public ExtendedKeyUsage(
        KeyPurposeId  usage)
    {
        this.seq = new DERSequence(usage);

        this.usageTable.put(usage, usage);
    }
    
    private ExtendedKeyUsage(
        ASN1Sequence  seq)
    {
        this.seq = seq;

        Enumeration e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1Encodable o = (ASN1Encodable)e.nextElement();
            if (!(o.toASN1Primitive() instanceof ASN1ObjectIdentifier))
            {
                throw new IllegalArgumentException("Only ASN1ObjectIdentifiers allowed in ExtendedKeyUsage.");
            }
            this.usageTable.put(o, o);
        }
    }

    public ExtendedKeyUsage(
        KeyPurposeId[]  usages)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != usages.length; i++)
        {
            v.add(usages[i]);
            this.usageTable.put(usages[i], usages[i]);
        }

        this.seq = new DERSequence(v);
    }

    /**
     * @deprecated use KeyPurposeId[] constructor.
     */
    public ExtendedKeyUsage(
        Vector usages)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        Enumeration         e = usages.elements();

        while (e.hasMoreElements())
        {
            ASN1Primitive  o = (ASN1Primitive)e.nextElement();

            v.add(o);
            this.usageTable.put(o, o);
        }

        this.seq = new DERSequence(v);
    }

    public boolean hasKeyPurposeId(
        KeyPurposeId keyPurposeId)
    {
        return (usageTable.get(keyPurposeId) != null);
    }
    
    /**
     * Returns all extended key usages.
     * The returned vector contains DERObjectIdentifiers.
     * @return An array with all key purposes.
     */
    public KeyPurposeId[] getUsages()
    {
        KeyPurposeId[] temp = new KeyPurposeId[seq.size()];

        int i = 0;
        for (Enumeration it = seq.getObjects(); it.hasMoreElements();)
        {
            temp[i++] = KeyPurposeId.getInstance(it.nextElement());
        }
        return temp;
    }

    public int size()
    {
        return usageTable.size();
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
