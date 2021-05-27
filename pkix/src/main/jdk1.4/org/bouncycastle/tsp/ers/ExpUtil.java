package org.bouncycastle.tsp.ers;

class ExpUtil
{
    static IllegalStateException createIllegalState(String message, Throwable cause)
    {
        return new IllegalStateException(message + ": " + cause.toString());
    }
}
