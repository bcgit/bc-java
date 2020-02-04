package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.util.Encodable;

public interface HssPublicKey
    extends Encodable
{

    int getL();

    LMSPublicKeyParameters getLmsPublicKey();
}
