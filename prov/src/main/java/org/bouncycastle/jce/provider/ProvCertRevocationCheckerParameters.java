package org.bouncycastle.jce.provider;

import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;

/**
 * Revocation checker parameters which also carry the builder parameters the validation was started
 * with, so the certification path build for an indirect CRL's signer is held to the caller's
 * maximum path length and excluded certificates rather than the builder defaults.
 */
class ProvCertRevocationCheckerParameters
    extends PKIXCertRevocationCheckerParameters
{
    private final PKIXExtendedBuilderParameters builderParams;

    ProvCertRevocationCheckerParameters(PKIXExtendedParameters paramsPKIX, PKIXExtendedBuilderParameters builderParams,
        Date validDate, CertPath certPath, int index, X509Certificate signingCert, PublicKey workingPublicKey)
    {
        super(paramsPKIX, validDate, certPath, index, signingCert, workingPublicKey);

        this.builderParams = builderParams;
    }

    /**
     * Return the builder parameters of the path under validation, null if it was not started by a builder.
     */
    PKIXExtendedBuilderParameters getBuilderParams()
    {
        return builderParams;
    }

    static PKIXExtendedBuilderParameters getBuilderParams(PKIXCertRevocationCheckerParameters params)
    {
        if (params instanceof ProvCertRevocationCheckerParameters)
        {
            return ((ProvCertRevocationCheckerParameters)params).getBuilderParams();
        }
        return null;
    }
}
