package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Strings;

public class GeneralNames
    extends ASN1Object
{
    private final GeneralName[] names;

    private static GeneralName[] copy(GeneralName[] names)
    {
        GeneralName[] result = new GeneralName[names.length];
        System.arraycopy(names, 0, result, 0, names.length);
        return result;
    }

    public static GeneralNames getInstance(
        Object  obj)
    {
        if (obj instanceof GeneralNames)
        {
            return (GeneralNames)obj;
        }

        if (obj != null)
        {
            return new GeneralNames(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static GeneralNames getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return new GeneralNames(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GeneralNames fromExtensions(Extensions extensions, ASN1ObjectIdentifier extOID)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, extOID));
    }

    /**
     * Construct a GeneralNames object containing one GeneralName.
     * 
     * @param name the name to be contained.
     */
    public GeneralNames(
        GeneralName  name)
    {
        this.names = new GeneralName[] { name };
    }


    public GeneralNames(
        GeneralName[]  names)
    {
        this.names = copy(names);
    }

    private GeneralNames(
        ASN1Sequence  seq)
    {
        this.names = new GeneralName[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            names[i] = GeneralName.getInstance(seq.getObjectAt(i));
        }
    }

    public GeneralName[] getNames()
    {
        return copy(names);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * GeneralNames ::= SEQUENCE SIZE {1..MAX} OF GeneralName
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(names);
    }

    public String toString()
    {
        StringBuffer  buf = new StringBuffer();
        String        sep = Strings.lineSeparator();

        buf.append("GeneralNames:");
        buf.append(sep);

        for (int i = 0; i != names.length; i++)
        {
            buf.append("    ");
            buf.append(names[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
