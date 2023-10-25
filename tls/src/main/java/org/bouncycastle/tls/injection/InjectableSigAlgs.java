package org.bouncycastle.tls.injection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.sigalgs.*;

import java.io.IOException;
import java.security.*;
import java.util.*;

public class InjectableSigAlgs {

    private final List<InjectedSigAlgorithm> orderedSigs;
    private final Map<Integer, InjectedSigAlgorithm> code2sig;
    private final Map<String, InjectedSigAlgorithm> oid2sig;
    private final InjectedSigners signers;
    private final InjectedSigVerifiers verifiers;

    public InjectableSigAlgs() {
        this.orderedSigs = new LinkedList<>();
        this.code2sig = new HashMap<>();
        this.oid2sig = new HashMap<>();
        this.signers = new InjectedSigners();
        this.verifiers = new InjectedSigVerifiers();
    }

    InjectableSigAlgs(InjectableSigAlgs origin) { // clone constructor
        this.orderedSigs = new LinkedList<>(origin.orderedSigs);
        this.code2sig = new HashMap<>(origin.code2sig);
        this.oid2sig = new HashMap<>(origin.oid2sig);
        this.signers = new InjectedSigners(origin.signers);
        this.verifiers = new InjectedSigVerifiers(origin.verifiers);
    }

    public void add(String name,
                    ASN1ObjectIdentifier oid,
                    int signatureSchemeCodePoint,
                    SigAlgAPI api) {
        InjectedSigAlgorithm newAlg = new InjectedSigAlgorithm(name, oid, signatureSchemeCodePoint, api);
        orderedSigs.add(newAlg);
        code2sig.put(signatureSchemeCodePoint, newAlg);
        oid2sig.put(oid.toString(), newAlg);
        signers.add(name, api::sign);
        verifiers.add(signatureSchemeCodePoint, api::verifySignature, api::internalEncoding);
    }

    public boolean contain(int codePoint) {
        return code2sig.containsKey(codePoint);
    }

    public boolean contain(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        int codePoint = SignatureAndHashAlgorithmFactory.codePointFromSignatureAndHashAlgorithm(signatureAndHashAlgorithm);
        return code2sig.containsKey(codePoint);
    }

    public boolean contain(ASN1ObjectIdentifier oid) {
        for (InjectedSigAlgorithm sigAlgorithm : orderedSigs) {
            if (oid.equals(sigAlgorithm.oid()))
                return true;
        }
        return false;
    }

    public Collection<SignatureAndHashAlgorithm> asSigAndHashCollection() {
        return orderedSigs.stream().map(InjectedSigAlgorithm::signatureAndHashAlgorithm).toList();
    }

    public Collection<Integer> asCodePointCollection() {
        return orderedSigs.stream().map(InjectedSigAlgorithm::codePoint).toList();
    }

    public Collection<InjectedSigAlgorithm> asSigAlgCollection() {
        return orderedSigs;
    }

    public Iterable<String> names() {
        return signers.getNames();
    }

    ///// for BC TLS

    public Asn1Bridge asn1Bridge() {
        return new Asn1Bridge() {
            @Override
            public boolean isSupportedParameter(AsymmetricKeyParameter bcKey) {
                for (InjectedSigAlgorithm sigAlg : orderedSigs) {
                    if (sigAlg.isSupportedParameter(bcKey))
                        return true;
                }
                return false;
            }

            @Override
            public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo asnPrivateKey) throws IOException {
                AlgorithmIdentifier algId = asnPrivateKey.getPrivateKeyAlgorithm();
                ASN1ObjectIdentifier algOID = algId.getAlgorithm();
                String algKey = algOID.toString();
                return oid2sig.get(algKey).createPrivateKeyParameter(asnPrivateKey);
            }

            @Override
            public PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter bcPrivateKey, ASN1Set attributes) throws IOException {
                for (InjectedSigAlgorithm sigAlg : orderedSigs) {
                    if (sigAlg.isSupportedParameter(bcPrivateKey))
                        return sigAlg.createPrivateKeyInfo(bcPrivateKey, attributes);
                }
                throw new RuntimeException("Unsupported private key params were given");
            }

            @Override
            public AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo ansPublicKey, Object defaultParams) throws IOException {
                AlgorithmIdentifier algId = ansPublicKey.getAlgorithm();
                ASN1ObjectIdentifier algOID = algId.getAlgorithm();
                String algKey = algOID.toString();
                return oid2sig.get(algKey).createPublicKeyParameter(ansPublicKey, defaultParams);
            }

            @Override
            public SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter bcPublicKey) throws IOException {
                for (InjectedSigAlgorithm sigAlg : orderedSigs) {
                    if (sigAlg.isSupportedParameter(bcPublicKey))
                        return sigAlg.createSubjectPublicKeyInfo(bcPublicKey);
                }
                throw new RuntimeException("Unsupported public key params were given");
            }
        };
    }

    ;

    public MyTls13Verifier tls13VerifierFor(PublicKey key) throws InvalidKeyException {
        SignatureSpi spi = signatureSpiFor(key);


        return new MyTls13Verifier(key, spi);
    }

    public TlsVerifier tlsVerifierFor(JcaTlsCrypto crypto, PublicKey publicKey, int sigSchemeCodePoint) {
        return verifiers.tlsVerifier(crypto, publicKey, sigSchemeCodePoint);
    }

    public TlsSigner tlsSignerFor(JcaTlsCrypto crypto, PrivateKey privateKey) {
        return signers.tlsSigner(crypto, privateKey);
    }

    public SignatureSpi signatureSpiFor(Key publicOrPrivateKey) throws InvalidKeyException {
        SignatureSpi result = null;
        for (InjectedSigAlgorithm sigAlg : orderedSigs) {
            try {
                result = sigAlg.signatureSpi(publicOrPrivateKey);
            } catch (Exception e) {
                // SignatureSpi could not been created with this factory, continue with the next one
            }
            if (result != null)
                break;
        }

        if (result == null) {
            throw new InvalidKeyException("No known SignatureSpi for the passed public key of type " + publicOrPrivateKey.getClass().getName());
        }

        return result;
    }

}
