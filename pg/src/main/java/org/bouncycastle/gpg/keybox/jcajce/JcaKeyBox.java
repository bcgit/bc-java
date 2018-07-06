package org.bouncycastle.gpg.keybox.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.gpg.keybox.BlobVerifier;
import org.bouncycastle.gpg.keybox.KeyBox;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

public class JcaKeyBox
    extends KeyBox
{
    JcaKeyBox(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier)
        throws IOException, NoSuchProviderException, NoSuchAlgorithmException
    {
        super(encoding, fingerPrintCalculator, verifier);
    }

    JcaKeyBox(InputStream input, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier)
        throws IOException
    {
        super(input, fingerPrintCalculator, verifier);
    }
}
