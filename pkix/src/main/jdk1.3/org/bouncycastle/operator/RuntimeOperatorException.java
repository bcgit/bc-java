package org.bouncycastle.operator;

// NOTE: jdk1.3 overlay. RuntimeException(String, Throwable) is a Java 1.4 constructor absent on
// JDK 1.3. No 1.3 caller can observe a dropped cause: the two-arg constructor keeps the message
// verbatim and discards the cause. Keep both signatures in lockstep with base.
public class RuntimeOperatorException
    extends RuntimeException
{
    public RuntimeOperatorException(String msg)
    {
        super(msg);
    }

    public RuntimeOperatorException(String msg, Throwable cause)
    {
        super(msg);
    }
}
