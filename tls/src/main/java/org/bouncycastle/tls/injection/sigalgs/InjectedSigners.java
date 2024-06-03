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
public class InjectedSigners
{

    private final Map<String, SignerFunction> injectedSigners;

    public InjectedSigners()
    {
        this.injectedSigners = new HashMap<>();
    }

    public InjectedSigners(InjectedSigners origin)
    { // clone
        this.injectedSigners = new HashMap<>(origin.injectedSigners);
    }

    public void add(
            String algorithmFullName,
            SignerFunction fn)
    {
        injectedSigners.put(algorithmFullName, fn);
    }

    public boolean contain(String algorithmFullName)
    {
        return injectedSigners.containsKey(algorithmFullName);
    }

    public Iterable<String> getNames()
    {
        return injectedSigners.keySet();
    }

    public TlsSigner tlsSigner(
            JcaTlsCrypto crypto,
            PrivateKey privateKey,
            String algorithmFullName)
    {
        // privateKey.getAlgorithm() returns some generinc name, e.g., "DSA" or "SPHINCS+"
        // however, we assume that the full algorithm name (with params) has been registered with the signer function;
        // thus, we require algorithmFullName to be passed as an argument

        Object fn = injectedSigners.get(algorithmFullName);
        if (fn == null)
        {
            throw new RuntimeException("Algorithm " + algorithmFullName + " not found among signers.");
        }

        byte[] skEncoded = privateKey.getEncoded();
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(skEncoded);

        byte[] skBytes = info.getPrivateKey().getOctets();
        return new MyTlsSigner(crypto, skBytes, (SignerFunction) fn);
    }
}
