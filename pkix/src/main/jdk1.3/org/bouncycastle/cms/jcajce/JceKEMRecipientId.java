package org.bouncycastle.cms.jcajce;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.KEMRecipientId;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.PrincipalUtil;

public class JceKEMRecipientId
    extends KEMRecipientId
{
    private static X509Principal extractIssuer(X509Certificate certificate)
    {
        try
        {
            return PrincipalUtil.getIssuerX509Principal(certificate);
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.toString());
        }
    }


    /**
     * Construct a recipient id based on the issuer, serial number and subject key identifier (if present) of the passed in
     * certificate.
     *
     * @param certificate certificate providing the issue and serial number and subject key identifier.
     */
    public JceKEMRecipientId(X509Certificate certificate)
    {
        super(convertPrincipal(extractIssuer(certificate)), certificate.getSerialNumber(), CMSUtils.getSubjectKeyId(certificate));
    }

    /**
     * Construct a recipient id based on the provided issuer and serial number..
     *
     * @param issuer the issuer to use.
     * @param serialNumber  the serial number to use.
     */
    public JceKEMRecipientId(X509Principal issuer, BigInteger serialNumber)
    {
        super(convertPrincipal(issuer), serialNumber);
    }

    /**
     * Construct a recipient id based on the provided issuer, serial number, and subjectKeyId..
     *
     * @param issuer the issuer to use.
     * @param serialNumber  the serial number to use.
     * @param subjectKeyId the subject key ID to use.
     */
    public JceKEMRecipientId(X509Principal issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        super(convertPrincipal(issuer), serialNumber, subjectKeyId);
    }

    private static X500Name convertPrincipal(X509Principal issuer)
    {
        if (issuer == null)
        {
            return null;
        }

        return X500Name.getInstance(issuer.getEncoded());
    }
}
