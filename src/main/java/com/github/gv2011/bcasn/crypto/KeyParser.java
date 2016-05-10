package com.github.gv2011.bcasn.crypto;

import java.io.IOException;
import java.io.InputStream;

import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}
