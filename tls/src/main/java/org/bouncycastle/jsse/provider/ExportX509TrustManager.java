package org.bouncycastle.jsse.provider;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

interface ExportX509TrustManager
{
    BCX509ExtendedTrustManager unwrap();
}
