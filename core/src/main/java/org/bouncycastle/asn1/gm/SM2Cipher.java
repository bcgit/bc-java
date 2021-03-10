package org.bouncycastle.asn1.gm;

import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * GMT 0009-2012
 *
 * sm2 encrypted data specific struct
 *
 * @author Cliven
 * @since 2021-03-10 13:28:12
 */
public class SM2Cipher extends ASN1Object
{
    /*
     * SM2Cipher ::== SEQUENCE{
     *     XCoordinate          INTEGER,                --X Portion
     *     YCoordinate          INTEGER,                --Y Portion
     *     HASH                 OCTET STRING SIZE(32),  --Plaintext sm3 hash
     *     CipherText           OCTET STRING            --CipherText
     * }
     */

    private ASN1Integer xCoordinate;
    private ASN1Integer yCoordinate;
    private ASN1OctetString hash;
    private ASN1OctetString cipherText;

    public SM2Cipher()
    {
        super();
    }

    public SM2Cipher(ASN1Sequence seq)
    {
        Enumeration<?> e = seq.getObjects();
        xCoordinate = ASN1Integer.getInstance(e.nextElement());
        yCoordinate = ASN1Integer.getInstance(e.nextElement());
        hash = ASN1OctetString.getInstance(e.nextElement());
        cipherText = ASN1OctetString.getInstance(e.nextElement());
    }

    public static SM2Cipher getInstance(Object o)
    {
        if(o instanceof SM2Cipher)
        {
            return (SM2Cipher) o;
        }
        else if(o != null)
        {
            return new SM2Cipher(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public ASN1Integer getxCoordinate()
    {
        return xCoordinate;
    }

    public void setxCoordinate(ASN1Integer xCoordinate)
    {
        this.xCoordinate = xCoordinate;
    }

    public ASN1Integer getyCoordinate()
    {
        return yCoordinate;
    }

    public void setyCoordinate(ASN1Integer yCoordinate)
    {
        this.yCoordinate = yCoordinate;
    }

    public ASN1OctetString getHash()
    {
        return hash;
    }

    public void setHash(ASN1OctetString hash)
    {
        this.hash = hash;
    }

    public ASN1OctetString getCipherText()
    {
        return cipherText;
    }

    public void setCipherText(ASN1OctetString cipherText)
    {
        this.cipherText = cipherText;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(xCoordinate);
        v.add(yCoordinate);
        v.add(hash);
        v.add(cipherText);
        return new DERSequence(v);
    }
}
