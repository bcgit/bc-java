package org.bouncycastle.cert.plants;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1RelativeOID;

class Utils
{
    static void writeUint64(ByteArrayOutputStream baos, long v)
    {
        baos.write((byte)(v >>> 56));
        baos.write((byte)(v >>> 48));
        baos.write((byte)(v >>> 40));
        baos.write((byte)(v >>> 32));
        baos.write((byte)(v >>> 24));
        baos.write((byte)(v >>> 16));
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    static long readUint64(ByteArrayInputStream in) throws IOException
    {
        byte[] buf = new byte[8];
        if (in.read(buf) != 8)
        {
            throw new IOException("Truncated uint64");
        }
        return ((buf[0] & 0xFFL) << 56) |
            ((buf[1] & 0xFFL) << 48) |
            ((buf[2] & 0xFFL) << 40) |
            ((buf[3] & 0xFFL) << 32) |
            ((buf[4] & 0xFFL) << 24) |
            ((buf[5] & 0xFFL) << 16) |
            ((buf[6] & 0xFFL) << 8)  |
            (buf[7] & 0xFFL);
    }

    static void writeUint48(ByteArrayOutputStream baos, long v)
    {
        if (v < 0 || v > 0xFFFFFFFFFFFFL)
        {
            throw new IllegalArgumentException("uint48 out of range: " + v);
        }
        baos.write((byte)(v >>> 40));
        baos.write((byte)(v >>> 32));
        baos.write((byte)(v >>> 24));
        baos.write((byte)(v >>> 16));
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    static long readUint48(ByteArrayInputStream in) throws IOException
    {
        byte[] buf = new byte[6];
        if (in.read(buf) != 6)
        {
            throw new IOException("Truncated uint48");
        }
        return ((buf[0] & 0xFFL) << 40) |
            ((buf[1] & 0xFFL) << 32) |
            ((buf[2] & 0xFFL) << 24) |
            ((buf[3] & 0xFFL) << 16) |
            ((buf[4] & 0xFFL) << 8) |
            (buf[5] & 0xFFL);
    }

    static int readUint16(ByteArrayInputStream in) throws IOException
    {
        int b1 = in.read();
        int b2 = in.read();
        if ((b1 | b2) < 0)
        {
            throw new IOException("Truncated uint16");
        }
        return (b1 << 8) | b2;
    }

    static void writeUint16(ByteArrayOutputStream baos, int v)
    {
        baos.write((byte)(v >>> 8));
        baos.write((byte)v);
    }

    static long readUint64(byte[] data, int off)
    {
        return ((data[off] & 0xFFL) << 56) |
            ((data[off + 1] & 0xFFL) << 48) |
            ((data[off + 2] & 0xFFL) << 40) |
            ((data[off + 3] & 0xFFL) << 32) |
            ((data[off + 4] & 0xFFL) << 24) |
            ((data[off + 5] & 0xFFL) << 16) |
            ((data[off + 6] & 0xFFL) << 8) |
            (data[off + 7] & 0xFFL);
    }

    /**
     * Converts a dotted-decimal OID identifier (e.g. {@code "32473.1"}) into the
     * binary trust anchor ID encoding per Section 3 of
     * draft-ietf-tls-trust-anchor-ids: the base-128 encoded OID-component bytes
     * with no ASN.1 tag or length prefix.
     */
    static byte[] dottedDecimalToBinaryTrustAnchorID(String dotted)
    {
        // Reuse ASN1RelativeOID for the per-component base-128 encoding, then
        // strip its DER tag and length header so only the contents octets remain.
        ASN1RelativeOID relOid = new ASN1RelativeOID(dotted);
        byte[] encoded;
        try
        {
            encoded = relOid.getEncoded();
        }
        catch (IOException e)
        {
            // Encoding a RELATIVE-OID we just constructed in memory should not fail.
            throw new IllegalStateException("unable to encode RELATIVE-OID for " + dotted, e);
        }
        return stripDerHeader(encoded);
    }

    /**
     * Encodes a non-negative integer as base-128 OID component bytes (the
     * encoding used inside ASN.1 RELATIVE-OID contents). For zero, a single
     * zero byte is emitted. Values use minimal continuation bits.
     */
    static byte[] encodeBase128OidComponent(long value)
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("OID component cannot be negative");
        }
        if (value == 0)
        {
            return new byte[]{0};
        }
        int n = 0;
        long t = value;
        while (t > 0)
        {
            n++;
            t >>>= 7;
        }
        byte[] out = new byte[n];
        for (int i = n - 1; i >= 0; i--)
        {
            int b = (int)((value >>> (7 * i)) & 0x7F);
            if (i > 0)
            {
                b |= 0x80;
            }
            out[n - 1 - i] = (byte)b;
        }
        return out;
    }

    /**
     * Builds the binary trust anchor ID of an issuance log from a CA's binary
     * trust anchor ID and a log number, per Section 5.2 of
     * draft-ietf-plants-merkle-tree-certs-04: {@code CA_ID || base128(0) || base128(log_number)}.
     */
    static byte[] buildLogId(byte[] caId, long logNumber)
    {
        byte[] zero = encodeBase128OidComponent(0);
        byte[] logNumBytes = encodeBase128OidComponent(logNumber);
        byte[] out = new byte[caId.length + zero.length + logNumBytes.length];
        int pos = 0;
        System.arraycopy(caId, 0, out, pos, caId.length);
        pos += caId.length;
        System.arraycopy(zero, 0, out, pos, zero.length);
        pos += zero.length;
        System.arraycopy(logNumBytes, 0, out, pos, logNumBytes.length);
        return out;
    }

    /**
     * Strips the leading tag and length octets from a DER encoding, returning
     * just the contents octets.
     */
    static byte[] stripDerHeader(byte[] der)
    {
        if (der.length < 2)
        {
            throw new IllegalArgumentException("DER encoding too short");
        }
        int offset = 1; // skip single-byte tag
        int lengthByte = der[offset] & 0xFF;
        int contentLength;
        int headerLength;
        if ((lengthByte & 0x80) == 0)
        {
            contentLength = lengthByte;
            headerLength = 2;
        }
        else
        {
            int numLengthBytes = lengthByte & 0x7F;
            if (numLengthBytes == 0 || der.length < 2 + numLengthBytes)
            {
                throw new IllegalArgumentException("Invalid DER length encoding");
            }
            contentLength = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                contentLength = (contentLength << 8) | (der[2 + i] & 0xFF);
            }
            headerLength = 2 + numLengthBytes;
        }
        if (headerLength + contentLength != der.length)
        {
            throw new IllegalArgumentException("DER content length does not match");
        }
        byte[] out = new byte[contentLength];
        System.arraycopy(der, headerLength, out, 0, contentLength);
        return out;
    }
}
