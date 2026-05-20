package org.bouncycastle.est;

import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.est.EstIdentityLinking;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

/**
 * Helper for emitting the EST transport-identity-linking attribute (RFC 7030 §3.5)
 * into a PKCS#10 certification request, with RFC 7894-aware selection of the
 * attribute type.
 * <p>
 * <a href="https://tools.ietf.org/html/rfc7030#section-3.5">RFC 7030 §3.5</a>
 * originally tunnelled the {@code tls-unique} value through the overloaded
 * PKCS#9 {@code challengePassword} attribute.
 * <a href="https://tools.ietf.org/html/rfc7894#section-3.3">RFC 7894 §3.3</a>
 * introduced {@code id-aa-estIdentityLinking} as the unambiguous attribute for
 * the same purpose. Per
 * <a href="https://tools.ietf.org/html/rfc7894#section-4">RFC 7894 §4</a>,
 * clients that see {@code estIdentityLinking} in the server's CSR-Attributes
 * response SHOULD prefer it and SHOULD NOT also include
 * {@code challengePassword}; clients that do not have a response (or whose
 * response does not advertise it) should continue to use the legacy attribute
 * for compatibility.
 */
public class TlsUniqueAttributeUtil
{
    private TlsUniqueAttributeUtil()
    {
    }

    /**
     * Set the EST transport-identity-linking attribute on {@code builder} from
     * the supplied {@code tls-unique} channel-binding value. The attribute type
     * is chosen per RFC 7894 §4:
     * <ul>
     *   <li>If {@code csrAttrs} is non-null and advertises
     *       {@link PKCSObjectIdentifiers#id_aa_estIdentityLinking}, the value
     *       goes into an {@code id-aa-estIdentityLinking} attribute (preferred).</li>
     *   <li>Otherwise the value goes into the legacy
     *       {@link PKCSObjectIdentifiers#pkcs_9_at_challengePassword} attribute
     *       for compatibility with pre-RFC-7894 servers.</li>
     * </ul>
     * In both cases the value carried is the Base64 encoding of {@code tlsUnique}.
     *
     * @param builder    the PKCS#10 request builder being assembled.
     * @param tlsUnique  the raw {@code tls-unique} bytes (RFC 5929) for the current
     *                   TLS session.
     * @param csrAttrs   the CSR-Attributes response previously fetched from the
     *                   server, or {@code null} if none is available.
     */
    public static void setTlsUniqueAttribute(
        PKCS10CertificationRequestBuilder builder,
        byte[] tlsUnique,
        CSRAttributesResponse csrAttrs)
    {
        if (builder == null)
        {
            throw new NullPointerException("builder cannot be null");
        }
        if (tlsUnique == null)
        {
            throw new NullPointerException("tlsUnique cannot be null");
        }

        // -DM Base64.toBase64String
        String b64 = Base64.toBase64String(tlsUnique);

        if (csrAttrs != null && csrAttrs.hasRequirement(PKCSObjectIdentifiers.id_aa_estIdentityLinking))
        {
            // RFC 7894 §4: server advertised estIdentityLinking — use it,
            // do not also include the legacy challengePassword attribute.
            EstIdentityLinking linking = new EstIdentityLinking(b64);
            builder.setAttribute(PKCSObjectIdentifiers.id_aa_estIdentityLinking, linking.getValue());
        }
        else
        {
            // Legacy RFC 7030 §3.5 path.
            builder.setAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new DERPrintableString(b64));
        }
    }
}
