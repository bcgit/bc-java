package org.bouncycastle.cades;

import org.bouncycastle.cms.CMSException;

/**
 * Exception thrown when a CAdES builder cannot assemble a profile (e.g. the
 * signing certificate cannot be digested, the configured signature policy is
 * malformed, etc.). Sub-classes {@link CMSException} so callers that already
 * catch CMS exceptions can keep doing so.
 */
public class CAdESException
    extends CMSException
{
    public CAdESException(String msg)
    {
        super(msg);
    }

    public CAdESException(String msg, Exception cause)
    {
        super(msg, cause);
    }
}
