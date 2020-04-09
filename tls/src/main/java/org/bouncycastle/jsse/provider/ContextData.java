package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.net.ssl.X509ExtendedKeyManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

final class ContextData
{
    private final ProvSSLContextSpi context;
    private final JcaTlsCrypto crypto;
    private final X509ExtendedKeyManager x509KeyManager;
    private final BCX509ExtendedTrustManager x509TrustManager;
    private final ProvSSLSessionContext clientSessionContext;
    private final ProvSSLSessionContext serverSessionContext;

    private final Map<Integer, NamedGroupInfo> namedGroupMap;
    private final Map<Integer, SignatureSchemeInfo> signatureSchemeMap;

    ContextData(ProvSSLContextSpi context, JcaTlsCrypto crypto, X509ExtendedKeyManager x509KeyManager,
        BCX509ExtendedTrustManager x509TrustManager)
    {
        this.context = context;
        this.crypto = crypto;
        this.x509KeyManager = x509KeyManager;
        this.x509TrustManager = x509TrustManager;
        this.clientSessionContext = new ProvSSLSessionContext(this);
        this.serverSessionContext = new ProvSSLSessionContext(this);

        this.namedGroupMap = NamedGroupInfo.createNamedGroupMap(context, crypto);
        this.signatureSchemeMap = SignatureSchemeInfo.createSignatureSchemeMap(context, crypto);
    }

    List<NamedGroupInfo> getActiveNamedGroups(ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions)
    {
        return NamedGroupInfo.getActiveNamedGroups(namedGroupMap, sslParameters, activeProtocolVersions);
    }

    List<SignatureSchemeInfo> getActiveSignatureSchemes(ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions)
    {
        return SignatureSchemeInfo.getActiveSignatureSchemes(signatureSchemeMap, sslParameters, activeProtocolVersions);
    }

    ProvSSLContextSpi getContext()
    {
        return context;
    }

    JcaTlsCrypto getCrypto()
    {
        return crypto;
    }

    ProvSSLSessionContext getClientSessionContext()
    {
        return clientSessionContext;
    }

    ProvSSLSessionContext getServerSessionContext()
    {
        return serverSessionContext;
    }

    List<NamedGroupInfo> getNamedGroups(int[] namedGroups)
    {
        return NamedGroupInfo.getNamedGroups(namedGroupMap, namedGroups);
    }

    List<SignatureSchemeInfo> getSignatureSchemes(Vector<SignatureAndHashAlgorithm> sigAndHashAlgs)
    {
        return SignatureSchemeInfo.getSignatureSchemes(signatureSchemeMap, sigAndHashAlgs);
    }

    X509ExtendedKeyManager getX509KeyManager()
    {
        return x509KeyManager;
    }

    BCX509ExtendedTrustManager getX509TrustManager()
    {
        return x509TrustManager;
    }
}
