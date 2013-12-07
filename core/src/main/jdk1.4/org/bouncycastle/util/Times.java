package org.bouncycastle.util;

public final class Times
{
    public static long nanoTime()
    {
        return 1000000L * System.currentTimeMillis();
    }
}
