package org.bouncycastle.operator;

import java.io.IOException;

// NOTE: jdk1.3 overlay. Throwable.initCause() is a Java 1.4 API absent on JDK 1.3. JDK 1.3 has no
// Throwable.getCause() either, so no 1.3 caller can observe a dropped cause: the message is kept
// verbatim and the cause discarded.
public class OperatorStreamException
    extends IOException
{
    public OperatorStreamException(String msg, Throwable cause)
    {
        super(msg);
    }
}
