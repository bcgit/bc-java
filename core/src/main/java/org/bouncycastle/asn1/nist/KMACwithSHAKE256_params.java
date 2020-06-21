package org.bouncycastle.asn1.nist;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *   KMACwithSHAKE256-params ::= SEQUENCE {
 *      kMACOutputLength     INTEGER DEFAULT 512, -- Output length in bits
 *      customizationString  OCTET STRING DEFAULT ''H
 *    }
 * </pre>
 */
public class KMACwithSHAKE256_params
    extends ASN1Object
{
    private static final byte[] EMPTY_STRING = new byte[0];
    private static final int DEF_LENGTH = 512;

    private final int outputLength;
    private final byte[] customizationString;

    public KMACwithSHAKE256_params(int outputLength)
    {
        this.outputLength = outputLength;
        this.customizationString = EMPTY_STRING;
    }

    public KMACwithSHAKE256_params(int outputLength, byte[] customizationString)
    {
        this.outputLength = outputLength;
        this.customizationString = Arrays.clone(customizationString);
    }

    public static KMACwithSHAKE256_params getInstance(Object o)
    {
        if (o instanceof KMACwithSHAKE256_params)
        {
            return (KMACwithSHAKE256_params)o;
        }
        else if (o != null)
        {
            return new KMACwithSHAKE256_params(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private KMACwithSHAKE256_params(ASN1Sequence seq)
    {
        if (seq.size() > 2)
        {
            throw new IllegalArgumentException("sequence size greater than 2");
        }

        if (seq.size() == 2)
        {
            this.outputLength = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
            this.customizationString = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
        }
        else if (seq.size() == 1)
        {
            if (seq.getObjectAt(0) instanceof ASN1Integer)
            {
                this.outputLength = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
                this.customizationString = EMPTY_STRING;
            }
            else
            {
                this.outputLength = DEF_LENGTH;
                this.customizationString = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
            }
        }
        else
        {
            this.outputLength = DEF_LENGTH;
            this.customizationString = EMPTY_STRING;
        }
    }

    public int getOutputLength()
    {
        return outputLength;
    }

    public byte[] getCustomizationString()
    {
        return Arrays.clone(customizationString);
    }
    
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (outputLength != DEF_LENGTH)
        {
            v.add(new ASN1Integer(outputLength));
        }

        if (customizationString.length != 0)
        {
            v.add(new DEROctetString(getCustomizationString()));
        }

        return new DERSequence(v);
    }
}
