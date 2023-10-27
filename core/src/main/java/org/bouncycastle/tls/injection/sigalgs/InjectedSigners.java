package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

/**
 * This class holds a set of signers (e.g., for PQC)
 * and can build a TlsSigner for the given private key.
 * #tls-injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigners {

    private final Map<String, SignerFunction> injectedSigners;

    public InjectedSigners() {
        this.injectedSigners = new HashMap<>();
    }

    public InjectedSigners(InjectedSigners origin) { // clone
        this.injectedSigners = new HashMap<>(origin.injectedSigners);
    }

    public void add(String algorithmName, SignerFunction fn) {
        injectedSigners.put(algorithmName, fn);
    }

    public boolean contain(String name) {
        return injectedSigners.containsKey(name);
    }

    public Iterable<String> getNames() {
        return injectedSigners.keySet();
    }

    public TlsSigner tlsSigner(JcaTlsCrypto crypto, PrivateKey privateKey) {
        String algorithm = privateKey.getAlgorithm();

        Object fn = injectedSigners.get(algorithm);
        if (fn == null)
            throw new RuntimeException("Algorithm " + algorithm + " not found among signers.");

        byte[] sk = privateKey.getEncoded();
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(sk);

        byte[] sk2;
        try {
            sk2 = info.getPrivateKey().getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return new MyTlsSigner(crypto, sk2, (SignerFunction) fn);
    }
}
