package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;

/**
 * <pre>
 *   ExtensionReq ::= SEQUENCE SIZE (1..MAX) OF Extension
 * </pre>
 */
public class ExtensionReq
    extends ASN1Object
{
    private final Extension[] extensions;

    public static ExtensionReq getInstance(
        Object obj)
    {
        if (obj instanceof ExtensionReq)
        {
            return (ExtensionReq)obj;
        }

        if (obj != null)
        {
            return new ExtensionReq(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ExtensionReq getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Construct a ExtensionReq object containing one Extension.
     *
     * @param Extension the Extension to be contained.
     */
    public ExtensionReq(
        Extension Extension)
    {
        this.extensions = new Extension[]{Extension};
    }


    public ExtensionReq(
        Extension[] extensions)
    {
        this.extensions = Utils.clone(extensions);
    }

    private ExtensionReq(
        ASN1Sequence seq)
    {
        this.extensions = new Extension[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            extensions[i] = Extension.getInstance(seq.getObjectAt(i));
        }
    }

    public Extension[] getExtensions()
    {
        return Utils.clone(extensions);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(extensions);
    }


}
