package org.bouncycastle.cms;

/**
 * Exception thrown if an Evidence Record according to RFC4998 fails to containsHashValue.
 *
 * {@see <a href="https://tools.ietf.org/html/rfc4998">RFC4998</a>}
 */
public class EvidenceRecordValidationException
    extends Exception {

    public EvidenceRecordValidationException(final String message)
    {
        super(message);
    }
}
