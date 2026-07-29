package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Exceptions;

/**
 * The C509 encoding of the subjectPublicKey field (Sections 3.1.7 and 3.2.1 of
 * draft-ietf-cose-cbor-encoded-cert-20).
 * <p>
 * For rsaEncryption the two INTEGER value fields are carried as unwrapped unsigned
 * bignums, with the array and exponent omitted when the exponent is 65537. For
 * id-ecPublicKey Weierstrass keys the point may be compressed: a natively signed
 * certificate uses the SEC 1 octets 0x02/0x03/0x04, while a re-encoded certificate
 * uses 0xfe/0xfd in place of 0x02/0x03 to record that the DER encoding held an
 * uncompressed point. For everything else the BIT STRING value field (which must
 * have zero unused bits) is carried as a byte string.
 */
class C509PublicKeyCodec
{
    /**
     * Encode the subjectPublicKey item for the given algorithm.
     *
     * @param nativeForm true for a natively signed certificate (type 2).
     */
    static byte[] encodeSubjectPublicKey(C509AlgorithmIdentifier algorithm, SubjectPublicKeyInfo spki,
        boolean compressPoints, boolean nativeForm)
        throws IOException
    {
        if (spki.getPublicKeyData().getPadBits() != 0)
        {
            throw new IOException("C509 subjectPublicKey BIT STRING must have zero unused bits");
        }
        byte[] keyBytes = spki.getPublicKeyData().getBytes();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);

        Integer registryValue = algorithm.getRegistryValue();
        if (registryValue != null && registryValue.intValue() == C509PublicKeyAlgorithm.RSA)
        {
            BigInteger modulus;
            BigInteger exponent;
            try
            {
                ASN1Sequence rsaKey = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(keyBytes));
                if (rsaKey.size() != 2)
                {
                    throw new IOException("malformed RSA subjectPublicKey");
                }
                modulus = ASN1Integer.getInstance(rsaKey.getObjectAt(0)).getValue();
                exponent = ASN1Integer.getInstance(rsaKey.getObjectAt(1)).getValue();
            }
            catch (RuntimeException e)
            {
                throw Exceptions.ioException("malformed RSA subjectPublicKey", e);
            }
            if (modulus.signum() < 1 || exponent.signum() < 1)
            {
                // RFC 3279 sec. 2.3.1 declares modulus and publicExponent as INTEGERs, but
                // RSA requires positive values - reject non-positive ones at first sight
                throw new IOException("malformed RSA subjectPublicKey");
            }
            if (exponent.equals(BigInteger.valueOf(65537)))
            {
                out.writeByteString(BigIntegers.asUnsignedByteArray(modulus));
            }
            else
            {
                out.writeArrayHeader(2);
                out.writeByteString(BigIntegers.asUnsignedByteArray(modulus));
                out.writeByteString(BigIntegers.asUnsignedByteArray(exponent));
            }
            return bOut.toByteArray();
        }

        if (registryValue != null && C509PublicKeyAlgorithm.isWeierstrassPoint(registryValue.intValue())
            && compressPoints && keyBytes.length > 1 && keyBytes[0] == 0x04)
        {
            int coordLength = (keyBytes.length - 1) / 2;
            boolean yOdd = (keyBytes[keyBytes.length - 1] & 1) != 0;
            byte[] compressed = new byte[1 + coordLength];
            System.arraycopy(keyBytes, 1, compressed, 1, coordLength);
            if (nativeForm)
            {
                compressed[0] = (byte)(yOdd ? 0x03 : 0x02);
            }
            else
            {
                compressed[0] = (byte)(yOdd ? 0xFD : 0xFE);
            }
            out.writeByteString(compressed);
            return bOut.toByteArray();
        }

        out.writeByteString(keyBytes);
        return bOut.toByteArray();
    }

    /**
     * Reconstruct the SubjectPublicKeyInfo the given subjectPublicKey item stands for.
     */
    static SubjectPublicKeyInfo decodeSubjectPublicKey(C509AlgorithmIdentifier algorithm, byte[] cborItem)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(cborItem);
        Integer registryValue = algorithm.getRegistryValue();

        byte[] keyBytes;
        if (registryValue != null && registryValue.intValue() == C509PublicKeyAlgorithm.RSA)
        {
            BigInteger modulus, exponent;
            if (in.peekMajorType() == CBORType.ARRAY)
            {
                int count = in.readArrayHeader();
                if (count != 2)
                {
                    throw new IOException("C509 RSA subjectPublicKey array must have 2 elements");
                }
                modulus = C509ExtensionValueCodec.readBiguint(in);
                exponent = C509ExtensionValueCodec.readBiguint(in);
            }
            else
            {
                modulus = C509ExtensionValueCodec.readBiguint(in);
                exponent = BigInteger.valueOf(65537);
            }
            in.expectEnd();
            keyBytes = C509ExtensionValueCodec.derEncode(new DERSequence(
                new ASN1Encodable[]{ new ASN1Integer(modulus), new ASN1Integer(exponent) }));
        }
        else
        {
            keyBytes = in.readByteString();
            in.expectEnd();
            if (registryValue != null && C509PublicKeyAlgorithm.isWeierstrassPoint(registryValue.intValue()))
            {
                if (keyBytes.length < 2)
                {
                    throw new IOException("malformed C509 elliptic curve subjectPublicKey");
                }
                int pointType = keyBytes[0] & 0xFF;
                if (pointType == 0xFE || pointType == 0xFD)
                {
                    keyBytes = decompressPoint(registryValue.intValue(), pointType == 0xFD, keyBytes);
                }
            }
        }

        try
        {
            return new SubjectPublicKeyInfo(algorithm.toX509AlgorithmIdentifier(), keyBytes);
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("malformed C509 subjectPublicKey", e);
        }
    }

    /**
     * Expand a point recorded with the 0xfe/0xfd markers of Section 3.2.1 back to the
     * uncompressed form the DER encoding held.
     */
    private static byte[] decompressPoint(int publicKeyAlgorithm, boolean yOdd, byte[] markedPoint)
        throws IOException
    {
        ASN1ObjectIdentifier curveOid = C509PublicKeyAlgorithm.getCurveOID(publicKeyAlgorithm);
        X9ECParameters curveParameters = ECNamedCurveTable.getByOID(curveOid);
        if (curveParameters == null)
        {
            throw new IOException("named curve for C509 public key algorithm " + publicKeyAlgorithm
                + " is not available");
        }
        byte[] compressed = Arrays.clone(markedPoint);
        compressed[0] = (byte)(yOdd ? 0x03 : 0x02);
        try
        {
            ECPoint point = curveParameters.getCurve().decodePoint(compressed);
            return point.getEncoded(false);
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("malformed compressed point in C509 subjectPublicKey", e);
        }
    }

    private C509PublicKeyCodec()
    {
    }
}
