package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;

/**
 * Verify the correctness of an OpenPGP signature.
 */
public interface PGPSignatureVerifier {

    /**
     * Return <pre>true</pre> if the signature is correct, <pre>false</pre> otherwise.
     * @return whether signature is correct
     * @throws PGPException
     * @throws IOException
     */
    boolean verify() throws PGPException, IOException;
}
