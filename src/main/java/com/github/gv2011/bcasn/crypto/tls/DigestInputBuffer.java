package com.github.gv2011.bcasn.crypto.tls;

import java.io.ByteArrayOutputStream;

import com.github.gv2011.bcasn.crypto.Digest;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(Digest d)
    {
        d.update(this.buf, 0, count);
    }
}
