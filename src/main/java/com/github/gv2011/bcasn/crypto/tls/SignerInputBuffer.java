package com.github.gv2011.bcasn.crypto.tls;

import java.io.ByteArrayOutputStream;

import com.github.gv2011.bcasn.crypto.Signer;

class SignerInputBuffer extends ByteArrayOutputStream
{
    void updateSigner(Signer s)
    {
        s.update(this.buf, 0, count);
    }
}