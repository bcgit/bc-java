package org.bouncycastle.pqc.legacy.crypto.gemss;

public interface GeMSSEngineProvider
{
    GeMSSEngine get();

    int getN();
}
