package org.bouncycastle.asn1.x509;

// NOTE: jdk1.3 overlay. Exception(String, Throwable) is a Java 1.4 constructor absent on JDK 1.3
// (Throwable gained the two-arg constructor and initCause()/getCause() together in 1.4), so the
// base class will not compile here. No 1.3 caller can observe a dropped cause: the two-arg
// constructor keeps the message verbatim and discards the cause. Keep both signatures in lockstep
// with the base CRLValidatorException so callers compile unchanged.
public class CRLValidatorException
    extends Exception
{
    public CRLValidatorException(String msg)
    {
        super(msg);
    }

    public CRLValidatorException(String msg, Throwable cause)
    {
        super(msg);
    }
}
