package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public interface TlsContext {

    SecureRandom getSecureRandom();

    SecurityParameters getSecurityParameters();

    boolean isServer();

    ProtocolVersion getClientVersion();

    ProtocolVersion getServerVersion();

    Object getUserObject();

    void setUserObject(Object userObject);
}
