package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.Vector;

import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

final class ContextData
{
    private static final Set<BCCryptoPrimitive> TLS_CRYPTO_PRIMITIVES_BC = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;

    private final boolean fipsMode;
    private final JcaTlsCrypto crypto;
    private final BCX509ExtendedKeyManager x509KeyManager;
    private final BCX509ExtendedTrustManager x509TrustManager;
    private final Map<String, CipherSuiteInfo> supportedCipherSuites;
    private final Map<String, ProtocolVersion> supportedProtocols;
    private final String[] defaultCipherSuitesClient;
    private final String[] defaultCipherSuitesServer;
    private final String[] defaultProtocolsClient;
    private final String[] defaultProtocolsServer;
    private final ProvSSLSessionContext clientSessionContext;
    private final ProvSSLSessionContext serverSessionContext;
    private final NamedGroupInfo.PerContext namedGroups;
    private final SignatureSchemeInfo.PerContext signatureSchemes;

    ContextData(boolean fipsMode, JcaTlsCrypto crypto, BCX509ExtendedKeyManager x509KeyManager,
        BCX509ExtendedTrustManager x509TrustManager, Map<String, CipherSuiteInfo> supportedCipherSuites,
        Map<String, ProtocolVersion> supportedProtocols, String[] defaultCipherSuitesClient,
        String[] defaultCipherSuitesServer, String[] defaultProtocolsClient, String[] defaultProtocolsServer)
    {
        this.fipsMode = fipsMode;
        this.crypto = crypto;
        this.x509KeyManager = x509KeyManager;
        this.x509TrustManager = x509TrustManager;
        this.supportedCipherSuites = supportedCipherSuites;
        this.supportedProtocols = supportedProtocols;
        this.defaultCipherSuitesClient = defaultCipherSuitesClient;
        this.defaultCipherSuitesServer = defaultCipherSuitesServer;
        this.defaultProtocolsClient = defaultProtocolsClient;
        this.defaultProtocolsServer = defaultProtocolsServer;
        this.clientSessionContext = new ProvSSLSessionContext(this);
        this.serverSessionContext = new ProvSSLSessionContext(this);
        this.namedGroups = NamedGroupInfo.createPerContext(fipsMode, crypto);
        this.signatureSchemes = SignatureSchemeInfo.createPerContext(fipsMode, crypto, namedGroups);
    }

    int[] getActiveCipherSuites(JcaTlsCrypto crypto, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions)
    {
        String[] enabledCipherSuites = sslParameters.getCipherSuitesArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);

        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);

        int[] candidates = new int[enabledCipherSuites.length];

        int count = 0;
        for (String enabledCipherSuite : enabledCipherSuites)
        {
            CipherSuiteInfo candidate = supportedCipherSuites.get(enabledCipherSuite);
            if (null == candidate)
            {
                continue;
            }
            if (candidate.isTLSv13())
            {
                if (!post13Active)
                {
                    continue;
                }
            }
            else
            {
                if (!pre13Active)
                {
                    continue;
                }
            }
            if (!algorithmConstraints.permits(TLS_CRYPTO_PRIMITIVES_BC, enabledCipherSuite, null))
            {
                continue;
            }

            /*
             * TODO[jsse] SunJSSE also checks that the cipher suite is usable for at least one of
             * the active protocol versions. Also, if the cipher suite involves a key exchange,
             * there must be at least one suitable NamedGroup available.
             */

            candidates[count++] = candidate.getCipherSuite();
        }

        /*
         * TODO Move cipher suite management into CipherSuiteInfo (PerConnection/PerContext pattern
         * like NamedGroupInfo) to avoid unnecessary repetition of these sorts of checks.
         */
        int[] result = TlsUtils.getSupportedCipherSuites(crypto, candidates, 0, count);

        if (result.length < 1)
        {
            // TODO[jsse] Refactor so that this can be an SSLHandshakeException?
            throw new IllegalStateException("No usable cipher suites enabled");
        }

        return result;
    }

    ProtocolVersion[] getActiveProtocolVersions(ProvSSLParameters sslParameters)
    {
//        String[] enabledCipherSuites = sslParameters.getCipherSuitesArray();
        String[] enabledProtocols = sslParameters.getProtocolsArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        SortedSet<ProtocolVersion> result = new TreeSet<ProtocolVersion>(new Comparator<ProtocolVersion>()
        {
            public int compare(ProtocolVersion o1, ProtocolVersion o2)
            {
                return o1.isLaterVersionOf(o2) ? -1 : o2.isLaterVersionOf(o1) ? 1 : 0;
            }
        });

        for (String enabledProtocol : enabledProtocols)
        {
            ProtocolVersion candidate = supportedProtocols.get(enabledProtocol);
            if (null == candidate)
            {
                continue;
            }
            if (!algorithmConstraints.permits(TLS_CRYPTO_PRIMITIVES_BC, enabledProtocol, null))
            {
                continue;
            }

            /*
             * TODO[jsse] SunJSSE also checks that there is at least one "activatable" cipher suite
             * that could be used for this protocol version.
             */

            result.add(candidate);
        }

        if (result.isEmpty())
        {
            // TODO[jsse] Refactor so that this can be an SSLHandshakeException?
            throw new IllegalStateException("No usable protocols enabled");
        }

        return result.toArray(new ProtocolVersion[result.size()]);
    }

    ProvSSLSessionContext getClientSessionContext()
    {
        return clientSessionContext;
    }

    JcaTlsCrypto getCrypto()
    {
        return crypto;
    }

    String[] getDefaultCipherSuites(boolean isClient)
    {
        return implGetDefaultCipherSuites(isClient).clone();
    }

    String[] getDefaultProtocols(boolean isClient)
    {
        return implGetDefaultProtocols(isClient).clone();
    }

    ProvSSLParameters getDefaultSSLParameters(boolean isClient)
    {
        return new ProvSSLParameters(this, implGetDefaultCipherSuites(isClient), implGetDefaultProtocols(isClient));
    }

    ProvSSLParameters getSupportedSSLParameters(boolean isClient)
    {
        return new ProvSSLParameters(this, getSupportedCipherSuites(), getSupportedProtocols());
    }

    NamedGroupInfo.PerConnection getNamedGroupsClient(ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions)
    {
        return NamedGroupInfo.createPerConnectionClient(namedGroups, sslParameters, activeProtocolVersions);
    }

    NamedGroupInfo.PerConnection getNamedGroupsServer(ProvSSLParameters sslParameters,
        ProtocolVersion negotiatedVersion)
    {
        return NamedGroupInfo.createPerConnectionServer(namedGroups, sslParameters, negotiatedVersion);
    }

    ProvSSLSessionContext getServerSessionContext()
    {
        return serverSessionContext;
    }

    SignatureSchemeInfo.PerConnection getSignatureSchemesClient(ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions, NamedGroupInfo.PerConnection namedGroups)
    {
        return SignatureSchemeInfo.createPerConnectionClient(signatureSchemes, sslParameters, activeProtocolVersions,
            namedGroups);
    }

    SignatureSchemeInfo.PerConnection getSignatureSchemesServer(ProvSSLParameters sslParameters,
        ProtocolVersion negotiatedVersion, NamedGroupInfo.PerConnection namedGroups)
    {
        return SignatureSchemeInfo.createPerConnectionServer(signatureSchemes, sslParameters, negotiatedVersion,
            namedGroups);
    }

    List<SignatureSchemeInfo> getSignatureSchemes(Vector<SignatureAndHashAlgorithm> sigAndHashAlgs)
    {
        return SignatureSchemeInfo.getSignatureSchemes(signatureSchemes, sigAndHashAlgs);
    }

    String[] getSupportedCipherSuites()
    {
        return JsseUtils.getKeysArray(supportedCipherSuites);
    }

    String[] getSupportedCipherSuites(String[] cipherSuites)
    {
        if (null == cipherSuites)
        {
            throw new NullPointerException("'cipherSuites' cannot be null");
        }

        ArrayList<String> result = new ArrayList<String>(cipherSuites.length);
        for (String cipherSuite : cipherSuites)
        {
            if (TlsUtils.isNullOrEmpty(cipherSuite))
            {
                throw new IllegalArgumentException("'cipherSuites' cannot contain null or empty string elements");
            }

            if (supportedCipherSuites.containsKey(cipherSuite))
            {
                result.add(cipherSuite);
            }
        }

        // NOTE: This method must always return a copy, so no fast path when all supported
        return JsseUtils.getArray(result);
    }

    String[] getSupportedProtocols()
    {
        return JsseUtils.getKeysArray(supportedProtocols);
    }

    BCX509ExtendedKeyManager getX509KeyManager()
    {
        return x509KeyManager;
    }

    BCX509ExtendedTrustManager getX509TrustManager()
    {
        return x509TrustManager;
    }

    boolean isFipsMode()
    {
        return fipsMode;
    }

    boolean isSupportedProtocols(String[] protocols)
    {
        if (protocols == null)
        {
            return false;
        }
        for (String protocol : protocols)
        {
            if (protocol == null || !supportedProtocols.containsKey(protocol))
            {
                return false;
            }
        }
        return true;
    }

    void updateDefaultSSLParameters(ProvSSLParameters sslParameters, boolean isClient)
    {
        if (sslParameters.getCipherSuitesArray() == implGetDefaultCipherSuites(!isClient))
        {
            sslParameters.setCipherSuitesArray(implGetDefaultCipherSuites(isClient));
        }
        if (sslParameters.getProtocolsArray() == implGetDefaultProtocols(!isClient))
        {
            sslParameters.setProtocolsArray(implGetDefaultProtocols(isClient));
        }
    }

    String validateNegotiatedCipherSuite(ProvSSLParameters sslParameters, int cipherSuite)
    {
        // NOTE: The redundancy among these various checks is intentional
        String name = ProvSSLContextSpi.getCipherSuiteName(cipherSuite);
        if (null == name
            || !JsseUtils.contains(sslParameters.getCipherSuitesArray(), name)
            || !sslParameters.getAlgorithmConstraints().permits(TLS_CRYPTO_PRIMITIVES_BC, name, null)
            || !supportedCipherSuites.containsKey(name))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported ciphersuite: " + cipherSuite);
        }
        return name;
    }

    String validateNegotiatedProtocol(ProvSSLParameters sslParameters, ProtocolVersion protocol)
    {
        // NOTE: The redundancy among these various checks is intentional
        String name = ProvSSLContextSpi.getProtocolVersionName(protocol);
        if (null == name
            || !JsseUtils.contains(sslParameters.getProtocolsArray(), name)
            || !sslParameters.getAlgorithmConstraints().permits(TLS_CRYPTO_PRIMITIVES_BC, name, null)
            || !supportedProtocols.containsKey(name))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported protocol: " + protocol);
        }
        return name;
    }

    private String[] implGetDefaultCipherSuites(boolean isClient)
    {
        return isClient ? defaultCipherSuitesClient : defaultCipherSuitesServer;
    }

    private String[] implGetDefaultProtocols(boolean isClient)
    {
        return isClient ? defaultProtocolsClient : defaultProtocolsServer;
    }
}
