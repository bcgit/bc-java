package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.Asn1Bridge;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;

public interface SigAlgAPI extends AsymmetricKeyInfoConverter,
                                   Asn1Bridge
{

    ///// BC <-> ASN.1 converters /////

    /**
     * Checks whether the given BC key (public or private) can be converted to ASN.1.
     *
     * @param bcKey an internal BC representation of a public or a private key
     *              that has to be converted to ASN.1
     * @return returns true, iff bcKey is of known type and can be converted to ASN.1
     * (i.e., a PrivateKeyInfo or SubjectPublicKeyInfo instance)
     */
    boolean isSupportedParameter(AsymmetricKeyParameter bcKey);

    boolean isSupportedPublicKey(Key key);
    boolean isSupportedPrivateKey(Key key);

    /**
     * Converts the given private key from ASN.1 to the internal BC representation.
     *
     * @param asnPrivateKey private key in the ASN.1 notation
     * @return internal BC representation of the private key
     * @throws IOException
     */
    AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo asnPrivateKey) throws IOException;


    /**
     * Converts the given private key from the internal BC representation to the ASN.1 notation.
     *
     * @param bcPrivateKey internal BC representation of a private key
     * @param attributes   ASN.1 attributes to be embedded into the ASN.1 representation
     * @return ASN.1 representation of the private key
     * @throws IOException
     */
    PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter bcPrivateKey, ASN1Set attributes) throws IOException;


    /**
     * Converts the given public key from ASN.1 to the internal BC representation.
     *
     * @param ansPublicKey  public key in the ASN.1 notation
     * @param defaultParams some default parameters (currently, null is passed)
     * @return internal BC representation of the public key
     * @throws IOException
     */
    AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo ansPublicKey, Object defaultParams) throws IOException;

    /**
     * Converts the given public key from the internal BC representation to the ASN.1 notation.
     *
     * @param bcPublicKey internal BC representation of a public key
     * @return ASN.1 representation of the public key
     * @throws IOException
     */
    SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter bcPublicKey) throws IOException;


    ///// AsymmetricKeyInfoConverter /////
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException;

    ///// Encodings /////
    byte[] internalEncodingFor(PublicKey key);
    byte[] internalEncodingFor(PrivateKey key);

    ///// sign & verify /////
    byte[] sign(JcaTlsCrypto crypto, byte[] message, byte[] privateKey)
            throws IOException, Exception;

    boolean verifySignature(byte[] message, byte[] publicKey, DigitallySigned signature);

    ///// SPI /////

    /**
     * Constructs a Java Service Provider Interface (SPI) driver for the current signature algorithm.
     * This driver will be used by the DirectSignatureSpi of the TLS injection mechanism.
     * @param key a public or a private key
     * @return a SignatureSpi instance (we suggest using our UniversalSignatureSpi class for that)
     */
    SignatureSpi signatureSpi(Key key);
}
