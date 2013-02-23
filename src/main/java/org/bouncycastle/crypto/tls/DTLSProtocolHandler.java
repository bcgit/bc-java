package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public class DTLSProtocolHandler {

    private final SecureRandom secureRandom;

    public DTLSProtocolHandler(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    public DTLSTransport connect(DatagramTransport transport) {
        return new DTLSTransport(transport);
        
//        if (client_version.isDTLS())
//        {
//            for (int cipherSuite : offeredCipherSuites)
//            {
//                switch (cipherSuite)
//                {
//                case CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5:
//                case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
//                case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
//                case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
//                case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
//                case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
//                    throw new IllegalStateException("Client offered an RC4 cipher suite: RC4 MUST NOT be used with DTLS");
//                }
//            }
//        }
    }
}
