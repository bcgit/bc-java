package org.bouncycastle.jce.provider;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;

/**
 * A failure to establish a certificate's revocation status by one means - OCSP, or CRLs - which
 * leaves the other free to be tried.
 */
class RecoverableCertPathValidatorException
    extends CertPathValidatorException
{
    private final boolean reportedOverFallback;

    public RecoverableCertPathValidatorException(String msg, Throwable cause, CertPath certPath, int index)
    {
        this(msg, cause, certPath, index, false);
    }

    /**
     * @param reportedOverFallback true if this failure says what a responder or its response did,
     * and so is the one to report should the fallback fail to settle the status as well; false
     * if it only says that this means was not available, when the fallback's own failure is the
     * one to report.
     */
    RecoverableCertPathValidatorException(String msg, Throwable cause, CertPath certPath, int index, boolean reportedOverFallback)
    {
        super(msg, cause, certPath, index);
        this.reportedOverFallback = reportedOverFallback;
    }

    boolean isReportedOverFallback()
    {
        return reportedOverFallback;
    }
}
