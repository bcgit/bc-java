package org.bouncycastle.cbor.c509;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;

/**
 * A C509 private key structure (Section 3.6 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * C509PrivateKey = [
 *    C509PrivateKeyType: int,
 *    subjectPrivateKeyAlgorithm: AlgorithmIdentifier,
 *    subjectPrivateKey: any,
 * ]
 * </pre>
 * For type 0 the subjectPrivateKey is the PrivateKey OCTET STRING value field of
 * RFC 5958 as a CBOR byte string; for type 1 it is a COSE_Key structure (RFC 9052),
 * carried here uninterpreted. The subjectPrivateKeyAlgorithm draws from the C509
 * Public Key Algorithms Registry (Section 8.15).
 * <p>
 * The structure transports secret material, so it is {@link Destroyable}: after
 * {@link #destroy()} the key bytes are zeroized and the accessors fail.
 */
public class C509PrivateKey
    implements Destroyable
{
    /** subjectPrivateKey is the RFC 5958 PrivateKey OCTET STRING value field as a byte string. */
    public static final int TYPE_ASYMMETRIC_KEY_PACKAGE = 0;
    /** subjectPrivateKey is a COSE_Key structure (RFC 9052) containing a private key. */
    public static final int TYPE_COSE_KEY = 1;

    private final int privateKeyType;
    private final C509AlgorithmIdentifier algorithm;
    private final byte[] subjectPrivateKeyItem;

    private volatile boolean destroyed = false;

    private C509PrivateKey(int privateKeyType, C509AlgorithmIdentifier algorithm, byte[] subjectPrivateKeyItem)
    {
        this.privateKeyType = privateKeyType;
        this.algorithm = algorithm;
        this.subjectPrivateKeyItem = subjectPrivateKeyItem;
    }

    /**
     * Parse a C509 private key structure from its CBOR encoding.
     */
    public static C509PrivateKey getInstance(byte[] encoding)
        throws IOException
    {
        CBORDecoder in = new CBORDecoder(encoding);
        int count = in.readArrayHeader();
        if (count != 3)
        {
            throw new IOException("C509PrivateKey array must have 3 elements");
        }
        C509PrivateKey key = parse(in);
        in.expectEnd();
        return key;
    }

    static C509PrivateKey parse(CBORDecoder in)
        throws IOException
    {
        int type = in.readInt();
        if (type != TYPE_ASYMMETRIC_KEY_PACKAGE && type != TYPE_COSE_KEY)
        {
            throw new IOException("unsupported C509PrivateKeyType: " + type);
        }
        C509AlgorithmIdentifier algorithm = C509AlgorithmIdentifier.parsePublicKeyAlgorithm(in);
        byte[] item = in.readEncodedItem();
        CBORDecoder itemIn = new CBORDecoder(item);
        if (type == TYPE_ASYMMETRIC_KEY_PACKAGE)
        {
            if (itemIn.peekMajorType() != CBORType.BYTE_STRING)
            {
                throw new IOException("C509PrivateKey type 0 subjectPrivateKey must be a byte string");
            }
        }
        else
        {
            if (itemIn.peekMajorType() != CBORType.MAP)
            {
                throw new IOException("C509PrivateKey type 1 subjectPrivateKey must be a COSE_Key map");
            }
        }
        return new C509PrivateKey(type, algorithm, item);
    }

    /**
     * Build a type 0 C509 private key from a PKCS#8 / RFC 5958 PrivateKeyInfo. The
     * privateKeyAlgorithm becomes the subjectPrivateKeyAlgorithm and the PrivateKey
     * OCTET STRING value field the subjectPrivateKey.
     */
    public static C509PrivateKey fromPrivateKeyInfo(PrivateKeyInfo privateKeyInfo)
        throws IOException
    {
        C509AlgorithmIdentifier algorithm = C509AlgorithmIdentifier.forPublicKeyAlgorithm(
            privateKeyInfo.getPrivateKeyAlgorithm());
        // getOctets() hands back the live array inside the PrivateKeyInfo - do not
        // modify it, only copy it into the CBOR item
        byte[] keyOctets = privateKeyInfo.getPrivateKey().getOctets();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeByteString(keyOctets);
        return new C509PrivateKey(TYPE_ASYMMETRIC_KEY_PACKAGE, algorithm, bOut.toByteArray());
    }

    /**
     * Return the PKCS#8 / RFC 5958 PrivateKeyInfo view of a type 0 C509 private key.
     *
     * @throws IllegalStateException if this is a type 1 (COSE_Key) structure or the
     *         key has been destroyed.
     */
    public PrivateKeyInfo toPrivateKeyInfo()
        throws IOException
    {
        checkNotDestroyed();
        if (privateKeyType != TYPE_ASYMMETRIC_KEY_PACKAGE)
        {
            throw new IllegalStateException("only a type 0 C509PrivateKey has a PrivateKeyInfo form");
        }
        // the PrivateKey OCTET STRING value field is carried opaque, so the
        // PrivateKeyInfo is assembled from components rather than re-encoded
        byte[] keyOctets = new CBORDecoder(subjectPrivateKeyItem).readByteString();
        try
        {
            return PrivateKeyInfo.getInstance(new DERSequence(new ASN1Encodable[]
                { new ASN1Integer(0), algorithm.toX509AlgorithmIdentifier(), new DEROctetString(keyOctets) }));
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("unable to build PrivateKeyInfo", e);
        }
    }

    /**
     * Return the private key type ({@link #TYPE_ASYMMETRIC_KEY_PACKAGE} or
     * {@link #TYPE_COSE_KEY}).
     */
    public int getPrivateKeyType()
    {
        return privateKeyType;
    }

    /**
     * Return the subject private key algorithm.
     */
    public C509AlgorithmIdentifier getSubjectPrivateKeyAlgorithm()
    {
        return algorithm;
    }

    /**
     * Return the CBOR encoding of the subjectPrivateKey item - the key material.
     */
    public byte[] getSubjectPrivateKeyEncoding()
    {
        checkNotDestroyed();
        return Arrays.clone(subjectPrivateKeyItem);
    }

    /**
     * Return the complete CBOR encoding of this structure.
     */
    public byte[] getEncoded()
        throws IOException
    {
        checkNotDestroyed();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder out = new CBOREncoder(bOut);
        encodeTo(out);
        return bOut.toByteArray();
    }

    void encodeTo(CBOREncoder out)
        throws IOException
    {
        checkNotDestroyed();
        out.writeArrayHeader(3);
        out.writeInteger(privateKeyType);
        algorithm.encodeTo(out);
        out.writeEncoded(subjectPrivateKeyItem);
    }

    public void destroy()
        throws DestroyFailedException
    {
        destroyed = true;
        Arrays.fill(subjectPrivateKeyItem, (byte)0);
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private void checkNotDestroyed()
    {
        if (destroyed)
        {
            throw new IllegalStateException("C509PrivateKey has been destroyed");
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof C509PrivateKey))
        {
            return false;
        }
        C509PrivateKey other = (C509PrivateKey)o;
        // the key material comparison is constant time, and the public terms are
        // combined with & so a mismatch cannot short-circuit around it
        return (privateKeyType == other.privateKeyType)
            & algorithm.equals(other.algorithm)
            & Arrays.constantTimeAreEqual(subjectPrivateKeyItem, other.subjectPrivateKeyItem);
    }

    public int hashCode()
    {
        // derived from public material only - never from the key bytes
        return privateKeyType ^ algorithm.hashCode();
    }

    public String toString()
    {
        return "C509PrivateKey[type=" + privateKeyType + "]";
    }
}
