package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * The method used to retrieve a related certificate, as defined by
 * draft-ietf-lamps-certdiscovery (Certificate Discovery in PKIX).
 *
 * <pre>
 *     CertDiscoveryMethod ::= CHOICE {
 *         byUri          [0] IMPLICIT CertLocation,
 *         byInclusion        Certificate,
 *         byLocalPolicy      NULL
 *     }
 *
 *     CertLocation ::= IA5String
 * </pre>
 *
 * Where {@code byUri} carries the URI from which the secondary certificate
 * may be downloaded, {@code byInclusion} embeds the secondary certificate
 * directly, and {@code byLocalPolicy} signals that the relying party is
 * expected to resolve the secondary certificate through local configuration.
 */
public class CertDiscoveryMethod
    extends ASN1Object
    implements ASN1Choice
{
    public static final int byUri         = 0;
    public static final int byInclusion   = 1;
    public static final int byLocalPolicy = 2;

    private final int type;
    private final ASN1Encodable value;

    /**
     * Create a {@code byUri} discovery method carrying the supplied URI.
     */
    public static CertDiscoveryMethod byUri(String uri)
    {
        return new CertDiscoveryMethod(byUri, new DERIA5String(uri));
    }

    /**
     * Create a {@code byInclusion} discovery method embedding the supplied
     * certificate directly.
     */
    public static CertDiscoveryMethod byInclusion(Certificate certificate)
    {
        return new CertDiscoveryMethod(byInclusion, certificate);
    }

    /**
     * Create a {@code byLocalPolicy} discovery method (the wire form is
     * ASN.1 NULL; the relying party resolves the certificate through local
     * configuration).
     */
    public static CertDiscoveryMethod byLocalPolicy()
    {
        return new CertDiscoveryMethod(byLocalPolicy, DERNull.INSTANCE);
    }

    private CertDiscoveryMethod(int type, ASN1Encodable value)
    {
        this.type = type;
        this.value = value;
    }

    public static CertDiscoveryMethod getInstance(Object obj)
    {
        if (obj == null || obj instanceof CertDiscoveryMethod)
        {
            return (CertDiscoveryMethod)obj;
        }

        ASN1Primitive prim;
        if (obj instanceof ASN1Encodable)
        {
            prim = ((ASN1Encodable)obj).toASN1Primitive();
        }
        else if (obj instanceof byte[])
        {
            try
            {
                prim = ASN1Primitive.fromByteArray((byte[])obj);
            }
            catch (java.io.IOException e)
            {
                throw new IllegalArgumentException("failed to parse CertDiscoveryMethod: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
        }

        if (prim instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject)prim;
            if (tagged.hasContextTag(byUri))
            {
                return new CertDiscoveryMethod(byUri, ASN1IA5String.getInstance(tagged, false));
            }
            throw new IllegalArgumentException("unknown tag in CertDiscoveryMethod: " + tagged.getTagNo());
        }
        if (prim instanceof ASN1Sequence)
        {
            return new CertDiscoveryMethod(byInclusion, Certificate.getInstance(prim));
        }
        if (prim instanceof ASN1Null)
        {
            return new CertDiscoveryMethod(byLocalPolicy, DERNull.INSTANCE);
        }

        throw new IllegalArgumentException("unknown object in CertDiscoveryMethod: " + prim.getClass().getName());
    }

    /**
     * Return one of {@link #byUri}, {@link #byInclusion}, {@link #byLocalPolicy}.
     */
    public int getType()
    {
        return type;
    }

    /**
     * Return the URI carried by a {@code byUri} method, or {@code null} for
     * the other alternatives.
     */
    public String getUri()
    {
        return type == byUri ? ((ASN1IA5String)value).getString() : null;
    }

    /**
     * Return the certificate carried by a {@code byInclusion} method, or
     * {@code null} for the other alternatives.
     */
    public Certificate getCertificate()
    {
        return type == byInclusion ? (Certificate)value : null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        switch (type)
        {
        case byUri:
            return new DERTaggedObject(false, byUri, value);
        case byInclusion:
            return value.toASN1Primitive();
        case byLocalPolicy:
            return DERNull.INSTANCE;
        default:
            throw new IllegalStateException("invalid CertDiscoveryMethod type: " + type);
        }
    }
}
