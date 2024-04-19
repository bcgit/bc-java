package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.Collection;

/**
 * A class representing injected signature algorithms. #tls-injection
 *
 * @author Sergejs Kozlovics
 */
public class InjectedSigAlgorithm
{
    private final String algorithmFullName;
    private final Collection<String> aliases;
    private final ASN1ObjectIdentifier oid;
    private final int signatureSchemeCodePoint;
    private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    // ^^^ Just splits the code point (a 2-byte integer) into two separate bytes:
    //     HighestByte(signatureSchemeCodePoint), LowestByte(signatureSchemeCodePoint).
    //     Actually, the highest (the second) byte does not necessarily correspond to the hash algorithm,
    //     but we still use the BC SignatureAndHashAlgorithm class since it is needed internally
    //     in many places within BC code.

    private final SigAlgAPI api;


    public InjectedSigAlgorithm(
            String algorithmFullName,
            Collection<String> aliases,
            ASN1ObjectIdentifier oid,
            int signatureSchemeCodePoint,
            SigAlgAPI api)
    {
        this.algorithmFullName = algorithmFullName;
        this.aliases = aliases;
        this.oid = oid;
        this.signatureSchemeCodePoint = signatureSchemeCodePoint;
        this.signatureAndHashAlgorithm = SignatureAndHashAlgorithmFactory.newFromCodePoint(signatureSchemeCodePoint);
        this.api = api;
    }

    public String name()
    {
        return this.algorithmFullName;
    }

    public Collection<String> aliases()
    {
        return this.aliases;
    }

    public ASN1ObjectIdentifier oid()
    {
        return this.oid;
    }

    public int codePoint()
    {
        return this.signatureSchemeCodePoint;
    }

    public SignatureAndHashAlgorithm signatureAndHashAlgorithm()
    {
        return this.signatureAndHashAlgorithm;
    }

    public boolean isSupportedParameter(AsymmetricKeyParameter param)
    {
        return this.api.isSupportedParameter(param);
    }

    public boolean isSupportedPublicKey(Key someKey) {
        return this.api.isSupportedPublicKey(someKey);
    }
    public boolean isSupportedPrivateKey(Key someKey) {
        return this.api.isSupportedPrivateKey(someKey);
    }

    public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException
    {
        return this.api.createPrivateKeyParameter(keyInfo);
    }

    public PrivateKeyInfo createPrivateKeyInfo(
            AsymmetricKeyParameter param,
            ASN1Set attributes) throws IOException
    {
        return this.api.createPrivateKeyInfo(param, attributes);
    }

    public AsymmetricKeyParameter createPublicKeyParameter(
            SubjectPublicKeyInfo keyInfo,
            Object defaultParams) throws IOException
    {
        return this.api.createPublicKeyParameter(keyInfo, defaultParams);
    }

    public SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException
    {
        return this.api.createSubjectPublicKeyInfo(publicKey);
    }

    public AsymmetricKeyInfoConverter converter()
    {
        return this.api;
    }

    public byte[] internalEncodingFor(PublicKey key)
    {
        return this.api.internalEncodingFor(key);
    }

    public byte[] internalEncodingFor(PrivateKey key)
    {
        return this.api.internalEncodingFor(key);
    }

    public SignatureSpi signatureSpi(Key key)
    {
        return this.api.signatureSpi(key);
    }
}
