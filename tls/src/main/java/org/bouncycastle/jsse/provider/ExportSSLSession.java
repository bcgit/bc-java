package org.bouncycastle.jsse.provider;

import org.bouncycastle.jsse.BCExtendedSSLSession;

interface ExportSSLSession
{
    BCExtendedSSLSession unwrap();
}
