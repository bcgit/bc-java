package org.bouncycastle.asn1.plants;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.*;

/**
 * ASN.1 representation of a cosigner signature used in {@link MTCProof}.
 *
 * <pre>
 * MTCSignature ::= SEQUENCE {
 *     cosigner_id   ASN1RelativeOID,
 *     signature     OCTET STRING
 * }
 * </pre>
 */
public class MTCSignature
    extends ASN1Object
{
    private final ASN1RelativeOID cosignerId;
    private final ASN1OctetString signature;

    public static MTCSignature getInstance(Object obj)
    {
        if (obj instanceof MTCSignature)
        {
            return (MTCSignature)obj;
        }
        else if (obj != null)
        {
            return new MTCSignature(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private MTCSignature(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Invalid MTCSignature sequence size");
        }

        this.cosignerId = ASN1RelativeOID.getInstance(seq.getObjectAt(0));
        this.signature = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public MTCSignature(byte[] cosignerId, byte[] signature)
    {
        this.cosignerId = ASN1RelativeOID.fromContents(cosignerId);
        this.signature = DEROctetString.fromContents(signature);
    }

    public MTCSignature(ASN1RelativeOID cosignerId, ASN1OctetString signature)
    {
        this.cosignerId = cosignerId;
        this.signature = signature;
    }

    public ASN1RelativeOID getCosignerId()
    {
        return cosignerId;
    }

    public ASN1OctetString getSignature()
    {
        return signature;
    }

    /**
     * Returns the raw value bytes of the RELATIVE‑OID (the OID components without the tag and length).
     * This is the internal encoding of the OID value.
     *
     * @return the OID value bytes
     * @throws IOException if DER encoding fails
     */
    public byte[] getCosignerIdValue()
        throws IOException
    {
        ASN1RelativeOID relativeOID = new ASN1RelativeOID(cosignerId.getId());
        byte[] full = relativeOID.getEncoded(ASN1Encoding.DER);

        int offset = 1; // skip tag (0x0D)

        int lengthByte = full[offset] & 0xFF;

        int length;
        int headerLength;

        if ((lengthByte & 0x80) == 0)
        {
            // short form length
            length = lengthByte;
            headerLength = 2;
        }
        else
        {
            // long form length
            int numLengthBytes = lengthByte & 0x7F;
            length = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                length = (length << 8) | (full[offset + 1 + i] & 0xFF);
            }
            headerLength = 2 + numLengthBytes;
        }

        return Arrays.copyOfRange(full, headerLength, headerLength + length);
    }

    /**
     * Returns the ASN.1 OCTET STRING containing the signature.
     */
    public byte[] getSignatureValue()
    {
        return signature.getOctets();
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(cosignerId);
        v.add(signature);

        return new DERSequence(v);
    }
}
