package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

interface SignatureCreator
{
    Signature createSignature(String sigName)
        throws NoSuchAlgorithmException, NoSuchProviderException;
}
