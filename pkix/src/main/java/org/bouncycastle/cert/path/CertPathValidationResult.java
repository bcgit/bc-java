package org.bouncycastle.cert.path;

public class CertPathValidationResult
{
    private final boolean isValid;
    private final CertPathValidationException cause;

    private int[] certIndexes;

    public CertPathValidationResult()
    {
        this.isValid = true;
        cause = null;
    }

    public CertPathValidationResult(int certIndex, int ruleIndex, CertPathValidationException cause)
    {
        this.isValid = false;
        this.cause = cause;
    }

    public CertPathValidationResult(int[] certIndexes, int[] ruleIndexes, CertPathValidationException[] cause)
    {
        // TODO
        this.isValid = false;
        this.cause = cause[0];
        this.certIndexes = certIndexes;
    }

    public boolean isValid()
    {
        return isValid;
    }

    public Exception getCause()
    {
        return cause;
    }

    public boolean isDetailed()
    {
        return this.certIndexes != null;
    }
}
