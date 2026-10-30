package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Exceptions;

/**
 * The method used to retrieve a related certificate, as defined by
 * draft-ietf-lamps-certdiscovery-04 (A Mechanism for X.509 Certificate Discovery).
 *
 * <pre>
 *     CertDiscoveryMethod ::= CHOICE {
 *         byUri          IA5String,
 *         byInclusion    Certificate,
 *         byLocalPolicy  NULL,
 *         byOther        [0] INSTANCE OF OTHER-DISCOVERY-METHOD
 *     }
 *
 *     OTHER-DISCOVERY-METHOD ::= TYPE-IDENTIFIER
 * </pre>
 *
 * The module is defined with EXPLICIT TAGS, so {@code byOther} is an explicitly
 * tagged SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id },
 * the same shape as an X.509 {@link OtherName}.
 * <p>
 * {@code byUri} carries the URI from which the Referenced Certificate may be
 * retrieved, {@code byInclusion} embeds the Referenced Certificate directly,
 * {@code byLocalPolicy} signals that the relying party is expected to resolve
 * it through local configuration, and {@code byOther} carries a method defined
 * outside the draft, identified by its type-id.
 * </p>
 */
public class CertDiscoveryMethod
    extends ASN1Object
    implements ASN1Choice
{
    /** Alternative index for {@code byUri}. */
    public static final int byUri         = 0;
    /** Alternative index for {@code byInclusion}. */
    public static final int byInclusion   = 1;
    /** Alternative index for {@code byLocalPolicy}. */
    public static final int byLocalPolicy = 2;
    /** Alternative index for {@code byOther} (carried on the wire under context tag [0]). */
    public static final int byOther       = 3;

    private static final int BY_OTHER_TAG = 0;

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

    /**
     * Create a {@code byOther} discovery method, an instance of the
     * OTHER-DISCOVERY-METHOD information object class.
     *
     * @param methodType  the type-id identifying the method.
     * @param methodValue the value associated with that type-id.
     */
    public static CertDiscoveryMethod byOther(ASN1ObjectIdentifier methodType, ASN1Encodable methodValue)
    {
        if (methodType == null)
        {
            throw new NullPointerException("'methodType' cannot be null");
        }
        if (methodValue == null)
        {
            throw new NullPointerException("'methodValue' cannot be null");
        }

        return new CertDiscoveryMethod(byOther, new OtherName(methodType, methodValue));
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
                throw Exceptions.illegalArgumentException("failed to parse CertDiscoveryMethod: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
        }

        if (prim instanceof ASN1IA5String)
        {
            return new CertDiscoveryMethod(byUri, prim);
        }
        if (prim instanceof ASN1Sequence)
        {
            return new CertDiscoveryMethod(byInclusion, Certificate.getInstance(prim));
        }
        if (prim instanceof ASN1Null)
        {
            return new CertDiscoveryMethod(byLocalPolicy, DERNull.INSTANCE);
        }
        if (prim instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = (ASN1TaggedObject)prim;
            if (tagged.hasContextTag(BY_OTHER_TAG))
            {
                return new CertDiscoveryMethod(byOther, OtherName.getInstance(ASN1Sequence.getInstance(tagged, true)));
            }
            throw new IllegalArgumentException("unknown tag in CertDiscoveryMethod: " + tagged.getTagNo());
        }

        throw new IllegalArgumentException("unknown object in CertDiscoveryMethod: " + prim.getClass().getName());
    }

    /**
     * Return one of {@link #byUri}, {@link #byInclusion}, {@link #byLocalPolicy},
     * {@link #byOther}.
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

    /**
     * Return the type-id of a {@code byOther} method, or {@code null} for the
     * other alternatives.
     */
    public ASN1ObjectIdentifier getOtherMethodType()
    {
        return type == byOther ? ((OtherName)value).getTypeID() : null;
    }

    /**
     * Return the value of a {@code byOther} method, or {@code null} for the
     * other alternatives.
     */
    public ASN1Encodable getOtherMethodValue()
    {
        return type == byOther ? ((OtherName)value).getValue() : null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        switch (type)
        {
        case byUri:
        case byInclusion:
            return value.toASN1Primitive();
        case byLocalPolicy:
            return DERNull.INSTANCE;
        case byOther:
            return new DERTaggedObject(true, BY_OTHER_TAG, value);
        default:
            throw new IllegalStateException("invalid CertDiscoveryMethod type: " + type);
        }
    }
}
