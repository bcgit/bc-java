package org.bouncycastle.tls.injection.kems;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

/**
 * The class for storing information of an injected key encapsulation mechanism (KEM ~ named group ~ curve).
 * (For the needs of Post-Quantum Cryptography, DH/ECC groups/curves have been replaced by KEMs.)
 * #tls-injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedKEM
{

    public interface TlsAgreementFactory
    {
        TlsAgreement create(
                JcaTlsCrypto crypto,
                boolean isServer);
    }

    private final int codePoint;
    private final String standardName;
    private final TlsAgreementFactory tlsAgreementFactory;

    public InjectedKEM(
            int kemCodePoint,
            String standardName,
            KemFactory kemFactory)
    {
        this(kemCodePoint,
                standardName,
                (crypto, isServer) -> new TlsAgreementForKEM(crypto, isServer, kemFactory.create()));

    }

    public InjectedKEM(
            int codePoint,
            String standardName,
            TlsAgreementFactory tlsAgreementFactory)
    {
        this.codePoint = codePoint;
        this.standardName = standardName;
        this.tlsAgreementFactory = tlsAgreementFactory;
    }

    public int codePoint()
    {
        return this.codePoint;
    }

    public String standardName()
    {
        return this.standardName;
    }

    public TlsAgreement tlsAgreement(
            JcaTlsCrypto crypto,
            boolean isServer)
    {
        return this.tlsAgreementFactory.create(crypto, isServer);
    }
}
