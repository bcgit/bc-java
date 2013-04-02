package org.bouncycastle.crypto.tls;

import org.bouncycastle.crypto.Digest;

interface TlsDigest extends Digest {

    TlsDigest fork();

}
