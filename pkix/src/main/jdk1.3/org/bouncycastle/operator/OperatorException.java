package org.bouncycastle.operator;

// NOTE: jdk1.3 overlay. Exception(String, Throwable) is a Java 1.4 constructor absent on JDK 1.3
// (Throwable gained the two-arg constructor and initCause()/getCause() together in 1.4), so the
// base class will not compile here. No 1.3 caller can observe a dropped cause: the two-arg
// constructor keeps the message verbatim and discards the cause. Keep both signatures in lockstep
// with the base OperatorException so callers compile unchanged.
public class OperatorException
    extends Exception
{
    public OperatorException(String msg, Throwable cause)
    {
        super(msg);
    }

    public OperatorException(String msg)
    {
        super(msg);
    }
}
