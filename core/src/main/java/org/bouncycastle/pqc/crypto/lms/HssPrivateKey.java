package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.util.Encodable;

public interface HssPrivateKey
    extends Encodable
{
    int getRemaining();

    int getL();

    List<LMSPrivateKeyParameters> getKeys();

    int getL(LMSPrivateKeyParameters privateKey);

    List<LMSSignature> getSig();

    BCHssPublicKey getPublicKey()
        throws LMSException;

    void addNewKey(int d, SecureRandom source)
            throws LMSException;
}
