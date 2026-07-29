package org.bouncycastle.est;

import org.bouncycastle.cbor.c509.C509CertificationRequestTemplate;

/**
 * Holder class for the response to a GET /csrattrs request made with the C509
 * certification request template media type (Section 4.4 of
 * draft-ietf-cose-cbor-encoded-cert-20). Mirrors {@link CSRRequestResponse}: a server
 * that has no template for the client answers 204 or 404, in which case
 * {@link #hasTemplate()} is false.
 */
public class C509CSRTemplateResponse
{
    private final C509CertificationRequestTemplate template;
    private final Source source;

    public C509CSRTemplateResponse(C509CertificationRequestTemplate template, Source source)
    {
        this.template = template;
        this.source = source;
    }

    /**
     * Return true if the server supplied a certification request template.
     */
    public boolean hasTemplate()
    {
        return template != null;
    }

    /**
     * Return the certification request template.
     *
     * @throws IllegalStateException if the server did not supply one.
     */
    public C509CertificationRequestTemplate getTemplate()
    {
        if (template == null)
        {
            throw new IllegalStateException("Response has no C509CertificationRequestTemplate.");
        }
        return template;
    }

    public Object getSource()
    {
        return source.getSession();
    }
}
