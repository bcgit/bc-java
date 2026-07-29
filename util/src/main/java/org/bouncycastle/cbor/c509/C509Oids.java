package org.bouncycastle.cbor.c509;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * Conversion between {@link ASN1ObjectIdentifier} and the unwrapped CBOR OID form of
 * RFC 9090, which is the byte string holding the content octets of the DER encoding
 * of the object identifier.
 */
class C509Oids
{
    /**
     * Return the DER content octets of the given object identifier.
     */
    static byte[] toContents(ASN1ObjectIdentifier oid)
    {
        byte[] der;
        try
        {
            der = oid.getEncoded();
        }
        catch (IOException e)
        {
            // an ASN1ObjectIdentifier always has an encoding
            throw Exceptions.illegalStateException("unable to encode OID: " + e.getMessage(), e);
        }
        // strip the identifier and length octets
        int lengthOctets = 1;
        int len = der[1] & 0xFF;
        if (len > 0x80)
        {
            lengthOctets += len - 0x80;
        }
        return Arrays.copyOfRange(der, 1 + lengthOctets, der.length);
    }

    /**
     * Reconstruct an object identifier from DER content octets.
     *
     * @throws IOException if the content octets are not a valid OID encoding.
     */
    static ASN1ObjectIdentifier fromContents(byte[] contents)
        throws IOException
    {
        if (contents.length < 1)
        {
            throw new IOException("CBOR OID content is empty");
        }
        try
        {
            return ASN1ObjectIdentifier.fromContents(contents);
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("malformed CBOR OID content", e);
        }
    }

    private C509Oids()
    {
    }
}
