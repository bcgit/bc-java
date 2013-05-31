package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public interface TlsContext
{

    SecureRandom getSecureRandom();

    SecurityParameters getSecurityParameters();

    boolean isServer();

    ProtocolVersion getClientVersion();

    ProtocolVersion getServerVersion();

    Object getUserObject();

    void setUserObject(Object userObject);

    /**
     * Export keying material according to RFC 5705: "Keying Material Exporters for TLS".
     *
     * @param asciiLabel    indicates which application will use the exported keys.
     * @param context_value allows the application using the exporter to mix its own data with the TLS PRF for
     *                      the exporter output.
     * @param length        the number of bytes to generate
     * @return a pseudorandom bit string of 'length' bytes generated from the master_secret.
     */
    byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length);
}
