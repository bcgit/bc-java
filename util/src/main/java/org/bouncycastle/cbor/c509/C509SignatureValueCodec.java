package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Exceptions;

/**
 * The C509 encoding of signature values (Sections 3.1.12 and 3.2.2 of
 * draft-ietf-cose-cbor-encoded-cert-20). ECDSA style signatures (the ECDSA and SM2
 * registry entries) are converted from the DER SEQUENCE of two INTEGERs to the fixed
 * width r || s byte string of Section 2.1 of RFC 9053; all other signature values
 * carry the BIT STRING value field as a byte string.
 */
class C509SignatureValueCodec
{
    /**
     * Encode a signature value item.
     *
     * @param signatureBytes the BIT STRING value field of the X.509 signature.
     * @param ecdsaWidth the field width in octets for an ECDSA style signature, or 0
     *        to derive it from the component lengths (rounded up to the nearest of
     *        the widths of the common curves).
     */
    static byte[] encodeSignatureValue(C509AlgorithmIdentifier signatureAlgorithm, byte[] signatureBytes,
        int ecdsaWidth)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);

        if (isEcdsaFormat(signatureAlgorithm))
        {
            BigInteger r;
            BigInteger s;
            try
            {
                ASN1Sequence rs = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(signatureBytes));
                if (rs.size() != 2)
                {
                    throw new IOException("malformed ECDSA signature value");
                }
                r = ASN1Integer.getInstance(rs.getObjectAt(0)).getValue();
                s = ASN1Integer.getInstance(rs.getObjectAt(1)).getValue();
            }
            catch (RuntimeException e)
            {
                throw Exceptions.ioException("malformed ECDSA signature value", e);
            }
            if (r.signum() < 1 || s.signum() < 1)
            {
                // RFC 3279 sec. 2.2.3 declares r and s as INTEGERs, but ECDSA requires
                // r, s >= 1: a non-positive component can never verify, so it is either
                // a broken encoder or an adversarial input - reject at first sight
                throw new IOException("malformed ECDSA signature value");
            }
            int rLen = BigIntegers.getUnsignedByteLength(r);
            int sLen = BigIntegers.getUnsignedByteLength(s);
            int width = ecdsaWidth;
            if (width <= 0)
            {
                width = deriveWidth(Math.max(rLen, sLen));
            }
            if (rLen > width || sLen > width)
            {
                throw new IOException("ECDSA signature components exceed the requested width");
            }
            byte[] joined = new byte[2 * width];
            BigIntegers.asUnsignedByteArray(r, joined, 0, width);
            BigIntegers.asUnsignedByteArray(s, joined, width, width);
            out.writeByteString(joined);
            return bOut.toByteArray();
        }

        out.writeByteString(signatureBytes);
        return bOut.toByteArray();
    }

    /**
     * Round a component length up to the width of the nearest common curve (P-256 and
     * friends at 32, P-384 at 48, brainpoolP512r1 at 64, P-521 at 66). The choice
     * only affects which of several equivalent C509 representations is produced -
     * reconstruction of the DER signature strips the padding again - so an unusual
     * curve size simply keeps its exact component length.
     */
    private static int deriveWidth(int componentLength)
    {
        if (componentLength <= 32)
        {
            return 32;
        }
        if (componentLength <= 48)
        {
            return 48;
        }
        if (componentLength <= 64)
        {
            return 64;
        }
        return Math.max(componentLength, 66);
    }

    /**
     * Decode a signature value item back to the BIT STRING value field of the X.509
     * signature.
     */
    static byte[] decodeSignatureValue(C509AlgorithmIdentifier signatureAlgorithm, CBORDecoder in)
        throws IOException
    {
        byte[] value = in.readByteString();
        if (!isEcdsaFormat(signatureAlgorithm))
        {
            return value;
        }
        if (value.length == 0 || (value.length & 1) != 0)
        {
            throw new IOException("C509 ECDSA signature value must hold two equal length integers");
        }
        int width = value.length / 2;
        BigInteger r = BigIntegers.fromUnsignedByteArray(value, 0, width);
        BigInteger s = BigIntegers.fromUnsignedByteArray(value, width, width);
        if (r.signum() < 1 || s.signum() < 1)
        {
            // an all-zero half can never be a valid ECDSA component (r, s >= 1)
            throw new IOException("malformed ECDSA signature value");
        }
        return C509ExtensionValueCodec.derEncode(new DERSequence(
            new ASN1Encodable[]{ new ASN1Integer(r), new ASN1Integer(s) }));
    }

    private static boolean isEcdsaFormat(C509AlgorithmIdentifier signatureAlgorithm)
    {
        Integer registryValue = signatureAlgorithm.getRegistryValue();
        return registryValue != null && C509SignatureAlgorithm.isEcdsaFormat(registryValue.intValue());
    }

    private C509SignatureValueCodec()
    {
    }
}
