package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.Vector;

import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

final class ContextData
{
    private final ProvSSLContextSpi context;
    private final JcaTlsCrypto crypto;
    private final BCX509ExtendedKeyManager x509KeyManager;
    private final BCX509ExtendedTrustManager x509TrustManager;
    private final ProvSSLSessionContext clientSessionContext;
    private final ProvSSLSessionContext serverSessionContext;
    private final NamedGroupInfo.PerContext namedGroups;
    private final SignatureSchemeInfo.PerContext signatureSchemes;

    ContextData(ProvSSLContextSpi context, JcaTlsCrypto crypto, BCX509ExtendedKeyManager x509KeyManager,
        BCX509ExtendedTrustManager x509TrustManager)
    {
        this.context = context;
        this.crypto = crypto;
        this.x509KeyManager = x509KeyManager;
        this.x509TrustManager = x509TrustManager;
        this.clientSessionContext = new ProvSSLSessionContext(this);
        this.serverSessionContext = new ProvSSLSessionContext(this);
        this.namedGroups = NamedGroupInfo.createPerContext(context.isFips(), crypto);
        this.signatureSchemes = SignatureSchemeInfo.createPerContext(context.isFips(), crypto, namedGroups);
    }

    NamedGroupInfo.PerConnection getNamedGroups(ProvSSLParameters sslParameters, ProtocolVersion[] activeProtocolVersions)
    {
        return NamedGroupInfo.createPerConnection(namedGroups, sslParameters, activeProtocolVersions);
    }

    List<SignatureSchemeInfo> getActiveCertsSignatureSchemes(boolean isServer, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions, NamedGroupInfo.PerConnection namedGroups)
    {
        return SignatureSchemeInfo.getActiveCertsSignatureSchemes(signatureSchemes, isServer, sslParameters,
            activeProtocolVersions, namedGroups);
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

    List<SignatureSchemeInfo> getSignatureSchemes(Vector<SignatureAndHashAlgorithm> sigAndHashAlgs)
    {
        return SignatureSchemeInfo.getSignatureSchemes(signatureSchemes, sigAndHashAlgs);
    }

    BCX509ExtendedKeyManager getX509KeyManager()
    {
        return x509KeyManager;
    }

    BCX509ExtendedTrustManager getX509TrustManager()
    {
        return x509TrustManager;
    }
}
