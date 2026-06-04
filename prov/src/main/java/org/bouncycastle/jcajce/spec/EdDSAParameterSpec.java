package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * ParameterSpec for EdDSA signature algorithms.
 * <p>
 * As well as selecting the curve (for key pair generation) the spec can carry the
 * RFC 8032 instance selectors used when signing or verifying: the <i>prehash</i> flag
 * (Ed25519ph / Ed448ph) and an optional <i>context</i> (Ed25519ctx, or the context
 * permitted by Ed448 / the prehash variants). A context, when supplied, must be at
 * most 255 bytes (RFC 8032 sec. 5.1 / 5.2). When neither prehash nor a non-empty
 * context is supplied the spec selects the pure variant, matching BC's historical
 * behaviour for the curve-name-only constructor.
 */
public class EdDSAParameterSpec
    implements AlgorithmParameterSpec
{
    public static final String Ed25519 = "Ed25519";
    public static final String Ed448 = "Ed448";

    private final String curveName;
    private final boolean prehash;
    private final byte[] context;

    /**
     * Base constructor - pure variant, no context.
     *
     * @param curveName name of the curve to specify.
     */
    public EdDSAParameterSpec(String curveName)
    {
        this(curveName, false, null);
    }

    /**
     * Constructor specifying the prehash (Ed25519ph / Ed448ph) selector.
     *
     * @param curveName name of the curve to specify.
     * @param prehash true to select the prehash (ph) variant.
     */
    public EdDSAParameterSpec(String curveName, boolean prehash)
    {
        this(curveName, prehash, null);
    }

    /**
     * Constructor specifying the prehash selector and a context.
     *
     * @param curveName name of the curve to specify.
     * @param prehash true to select the prehash (ph) variant.
     * @param context the RFC 8032 context (at most 255 bytes), or null for none.
     */
    public EdDSAParameterSpec(String curveName, boolean prehash, byte[] context)
    {
        if (curveName.equalsIgnoreCase(Ed25519))
        {
            this.curveName = Ed25519;
        }
        else if (curveName.equalsIgnoreCase(Ed448))
        {
            this.curveName = Ed448;
        }
        else if (curveName.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
        {
            this.curveName = Ed25519;
        }
        else if (curveName.equals(EdECObjectIdentifiers.id_Ed448.getId()))
        {
            this.curveName = Ed448;
        }
        else
        {
            throw new IllegalArgumentException("unrecognized curve name: " + curveName);
        }

        if (context != null && context.length > 255)
        {
            throw new IllegalArgumentException("context too long - must be at most 255 bytes");
        }

        this.prehash = prehash;
        this.context = Arrays.clone(context);
    }

    /**
     * Return the curve name specified by this parameterSpec.
     *
     * @return the name of the curve this parameterSpec specifies.
     */
    public String getCurveName()
    {
        return curveName;
    }

    /**
     * Return whether the prehash (ph) variant is selected.
     *
     * @return true if Ed25519ph / Ed448ph is selected, false for the pure / ctx variant.
     */
    public boolean isPrehash()
    {
        return prehash;
    }

    /**
     * Return the RFC 8032 context, or null if none was specified.
     *
     * @return a copy of the context, or null.
     */
    public byte[] getContext()
    {
        return Arrays.clone(context);
    }
}
