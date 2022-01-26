package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CRLException;

import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.jcajce.util.JcaJceHelper;

/**
 * This class exists to let {@link #equals(Object)} and {@link #hashCode()} methods be delegated efficiently
 * to the platform default implementations (especially important for compatibility of {@link #hashCode()}
 * calculations). Those methods fall back to calling {@link #getEncoded()} for third-party subclasses, and
 * this class allows us to avoid cloning the return value of {@link #getEncoded()} for those callers.
 */
class X509CRLInternal extends X509CRLImpl
{
    private final byte[] encoding;
    private final CRLException exception;

    X509CRLInternal(JcaJceHelper bcHelper, CertificateList c, String sigAlgName, byte[] sigAlgParams, boolean isIndirect,
        byte[] encoding, CRLException exception)
    {
        super(bcHelper, c, sigAlgName, sigAlgParams, isIndirect);

        this.encoding = encoding;
        this.exception = exception;
    }

    public byte[] getEncoded() throws CRLException
    {
        if (null != exception)
        {
            throw exception;
        }

        if (null == encoding)
        {
            throw new CRLException();
        }

        /*
         * NOTE: Don't clone this return value. See class javadoc for details. Any necessary cloning is
         * handled by the X509CRLObject that is holding this instance.
         */
        return encoding;
    }
}
