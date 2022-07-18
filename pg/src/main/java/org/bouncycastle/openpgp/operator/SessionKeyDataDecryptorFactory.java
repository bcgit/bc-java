package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPSessionKey;

public interface SessionKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    PGPSessionKey getSessionKey();
}
