package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

/**
 * GMT 0009-2012
 * <p>
 * sm2 encrypted data specific struct
 *
 *
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

    /**
     * Convert ASN.1 Struct to C1C3C2 format
     *
     * @return C1C3C2
     * @throws IOException
     */
    public byte[] convertC1C3C2() throws IOException
    {
        /*
         * construct GMT0009-2012 encrypted data struct
         */
        ByteArrayOutputStream stream = new ByteArrayOutputStream();


        final byte[] x = new byte[32];
        final byte[] y = new byte[32];

        byte[] tmp = BigIntegers.asUnsignedByteArray(getxCoordinate().getValue());
        System.arraycopy(tmp, 0, x, 32 - tmp.length, tmp.length);
        tmp = BigIntegers.asUnsignedByteArray(getyCoordinate().getValue());
        System.arraycopy(tmp, 0, y, 32 - tmp.length, tmp.length);

        // C1
        // read 1 byte for uncompressed point prefix 0x04
        stream.write(0x04);
        stream.write(x);
        stream.write(y);
        // C3
        stream.write(getHash().getOctets());
        // C2
        stream.write(getCipherText().getOctets());
        stream.flush();
        return stream.toByteArray();
    }

    /**
     * Convert SM2 encrypted result format of c1c3c2 to ASN.1 SM2Cipher
     *
     * @param c1c3c2 encrypted result
     * @return SM2Cipher
     * @throws IOException
     */
    static public SM2Cipher fromC1C3C2(byte[] c1c3c2) throws IOException
    {
        /*
         * construct GMT0009-2012 encrypted data struct
         */
        ByteArrayInputStream stream = new ByteArrayInputStream(c1c3c2);
        // read 1 byte for uncompressed point prefix 0x04
        stream.read();
        final byte[] x = new byte[32];
        final byte[] y = new byte[32];
        final byte[] hash = new byte[32];
        int length = c1c3c2.length - 1 - 32 - 32 - 32;
        final byte[] cipherText = new byte[length];
        stream.read(x);
        stream.read(y);
        stream.read(hash);
        stream.read(cipherText);

        final SM2Cipher sm2Cipher = new SM2Cipher();
        sm2Cipher.setxCoordinate(new ASN1Integer(new BigInteger(1, x)));
        sm2Cipher.setyCoordinate(new ASN1Integer(new BigInteger(1, y)));
        sm2Cipher.setHash(new DEROctetString(hash));
        sm2Cipher.setCipherText(new DEROctetString(cipherText));
        return sm2Cipher;
    }
}
