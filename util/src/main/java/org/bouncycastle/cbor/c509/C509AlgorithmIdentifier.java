package org.bouncycastle.cbor.c509;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Integers;

/**
 * A C509 AlgorithmIdentifier, either a registered CBOR int or an unwrapped CBOR OID
 * (RFC 9090) optionally followed by the DER-encoded parameters as a CBOR byte string
 * (Sections 3.1.3 and 3.1.7 of draft-ietf-cose-cbor-encoded-cert-20):
 * <pre>
 * AlgorithmIdentifier = int / ~oid / [ algorithm: ~oid, parameters: bytes ]
 * </pre>
 * The meaning of a registered int depends on which registry the field draws from
 * (signature algorithms, Section 8.14, or public key algorithms, Section 8.15), so
 * instances are created through the registry-specific factory methods, and every
 * instance carries its resolved X.509 {@link AlgorithmIdentifier}.
 */
public class C509AlgorithmIdentifier
{
    private final Integer value;
    private final ASN1ObjectIdentifier oid;
    private final byte[] parameters;
    private final AlgorithmIdentifier x509AlgorithmIdentifier;
    private final Integer registryValue;

    private C509AlgorithmIdentifier(Integer value, ASN1ObjectIdentifier oid, byte[] parameters,
        AlgorithmIdentifier x509AlgorithmIdentifier, Integer registryValue)
    {
        this.value = value;
        this.oid = oid;
        this.parameters = parameters;
        this.x509AlgorithmIdentifier = x509AlgorithmIdentifier;
        this.registryValue = registryValue;
    }

    /**
     * Build the C509 form of a signature AlgorithmIdentifier, using the registered int
     * where the C509 Signature Algorithms Registry (Section 8.14) has an entry for it,
     * and the unwrapped CBOR OID form otherwise.
     */
    public static C509AlgorithmIdentifier forSignatureAlgorithm(AlgorithmIdentifier algorithm)
    {
        return forAlgorithm(algorithm, C509SignatureAlgorithm.getValue(algorithm));
    }

    /**
     * Build the C509 form of a subject public key AlgorithmIdentifier, using the
     * registered int where the C509 Public Key Algorithms Registry (Section 8.15) has
     * an entry for it, and the unwrapped CBOR OID form otherwise.
     */
    public static C509AlgorithmIdentifier forPublicKeyAlgorithm(AlgorithmIdentifier algorithm)
    {
        return forAlgorithm(algorithm, C509PublicKeyAlgorithm.getValue(algorithm));
    }

    private static C509AlgorithmIdentifier forAlgorithm(AlgorithmIdentifier algorithm, Integer registryValue)
    {
        if (registryValue != null)
        {
            return new C509AlgorithmIdentifier(registryValue, null, null, algorithm, registryValue);
        }
        byte[] params = null;
        if (algorithm.getParameters() != null)
        {
            try
            {
                params = algorithm.getParameters().toASN1Primitive().getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException("unable to encode algorithm parameters", e);
            }
        }
        return new C509AlgorithmIdentifier(null, algorithm.getAlgorithm(), params, algorithm, null);
    }

    /**
     * Parse a signature AlgorithmIdentifier, resolving registered ints against the
     * C509 Signature Algorithms Registry (Section 8.14).
     */
    static C509AlgorithmIdentifier parseSignatureAlgorithm(CBORDecoder in)
        throws IOException
    {
        return parse(in, true);
    }

    /**
     * Parse a subject public key AlgorithmIdentifier, resolving registered ints
     * against the C509 Public Key Algorithms Registry (Section 8.15).
     */
    static C509AlgorithmIdentifier parsePublicKeyAlgorithm(CBORDecoder in)
        throws IOException
    {
        return parse(in, false);
    }

    private static C509AlgorithmIdentifier parse(CBORDecoder in, boolean signatureRegistry)
        throws IOException
    {
        int major = in.peekMajorType();
        if (major == CBORType.UNSIGNED_INTEGER || major == CBORType.NEGATIVE_INTEGER)
        {
            int value = in.readInt();
            AlgorithmIdentifier algId = signatureRegistry
                ? C509SignatureAlgorithm.getAlgorithmIdentifier(value)
                : C509PublicKeyAlgorithm.getAlgorithmIdentifier(value);
            if (algId == null)
            {
                throw new IOException("unknown C509 " + (signatureRegistry ? "signature" : "public key")
                    + " algorithm value: " + value);
            }
            Integer boxed = Integers.valueOf(value);
            return new C509AlgorithmIdentifier(boxed, null, null, algId, boxed);
        }

        ASN1ObjectIdentifier oid;
        byte[] params = null;
        if (major == CBORType.ARRAY)
        {
            int count = in.readArrayHeader();
            if (count != 2)
            {
                throw new IOException("C509 AlgorithmIdentifier array must have 2 elements");
            }
            oid = C509Oids.fromContents(in.readByteString());
            params = in.readByteString();
            if (params.length == 0)
            {
                throw new IOException("C509 AlgorithmIdentifier parameters cannot be empty");
            }
        }
        else if (major == CBORType.BYTE_STRING)
        {
            oid = C509Oids.fromContents(in.readByteString());
        }
        else
        {
            throw new IOException("C509 AlgorithmIdentifier expected, found major type " + major);
        }

        AlgorithmIdentifier algId;
        try
        {
            algId = (params == null)
                ? new AlgorithmIdentifier(oid)
                : new AlgorithmIdentifier(oid, ASN1Primitive.fromByteArray(params));
        }
        catch (RuntimeException e)
        {
            throw Exceptions.ioException("malformed C509 AlgorithmIdentifier parameters", e);
        }

        Integer registryValue = signatureRegistry
            ? C509SignatureAlgorithm.getValue(algId)
            : C509PublicKeyAlgorithm.getValue(algId);

        return new C509AlgorithmIdentifier(null, oid, params, algId, registryValue);
    }

    void encodeTo(CBOREncoder out)
        throws IOException
    {
        if (value != null)
        {
            out.writeInteger(value.intValue());
        }
        else if (parameters != null)
        {
            out.writeArrayHeader(2);
            out.writeByteString(C509Oids.toContents(oid));
            out.writeByteString(parameters);
        }
        else
        {
            out.writeByteString(C509Oids.toContents(oid));
        }
    }

    /**
     * Return true if this identifier is carried as a registered CBOR int on the wire.
     */
    public boolean isRegisteredValue()
    {
        return value != null;
    }

    /**
     * Return the registry value for the algorithm this identifier resolves to, whether
     * it is carried as an int or as an OID whose AlgorithmIdentifier matches a registry
     * entry, or null when the algorithm is not registered.
     */
    public Integer getRegistryValue()
    {
        return registryValue;
    }

    /**
     * Return the X.509 AlgorithmIdentifier this identifier stands for.
     */
    public AlgorithmIdentifier toX509AlgorithmIdentifier()
    {
        return x509AlgorithmIdentifier;
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof C509AlgorithmIdentifier))
        {
            return false;
        }
        C509AlgorithmIdentifier other = (C509AlgorithmIdentifier)o;
        if (value != null)
        {
            return value.equals(other.value);
        }
        return other.value == null && oid.equals(other.oid) && Arrays.areEqual(parameters, other.parameters);
    }

    public int hashCode()
    {
        if (value != null)
        {
            return value.intValue();
        }
        return oid.hashCode() ^ Arrays.hashCode(parameters);
    }
}
