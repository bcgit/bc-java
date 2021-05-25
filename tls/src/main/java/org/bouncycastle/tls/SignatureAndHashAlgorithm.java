package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * RFC 5246 7.4.1.4.1
 */
public class SignatureAndHashAlgorithm
{
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP256r1tls13_sha256 =
        create(SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP384r1tls13_sha384 =
        create(SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384);
    public static final SignatureAndHashAlgorithm ecdsa_brainpoolP512r1tls13_sha512 =
        create(SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512);
    public static final SignatureAndHashAlgorithm ed25519 =
        create(SignatureScheme.ed25519);
    public static final SignatureAndHashAlgorithm ed448 =
        create(SignatureScheme.ed448);
    public static final SignatureAndHashAlgorithm gostr34102012_256 =
        create(HashAlgorithm.Intrinsic, SignatureAlgorithm.gostr34102012_256);
    public static final SignatureAndHashAlgorithm gostr34102012_512 =
        create(HashAlgorithm.Intrinsic, SignatureAlgorithm.gostr34102012_512);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha256 =
        create(SignatureScheme.rsa_pss_rsae_sha256);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha384 =
        create(SignatureScheme.rsa_pss_rsae_sha384);
    public static final SignatureAndHashAlgorithm rsa_pss_rsae_sha512 =
        create(SignatureScheme.rsa_pss_rsae_sha512);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha256 =
        create(SignatureScheme.rsa_pss_pss_sha256);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha384 =
        create(SignatureScheme.rsa_pss_pss_sha384);
    public static final SignatureAndHashAlgorithm rsa_pss_pss_sha512 =
        create(SignatureScheme.rsa_pss_pss_sha512);

    public static SignatureAndHashAlgorithm getInstance(short hashAlgorithm, short signatureAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.Intrinsic:
            return getInstanceIntrinsic(signatureAlgorithm);
        default:
            return create(hashAlgorithm, signatureAlgorithm);
        }
    }

    private static SignatureAndHashAlgorithm getInstanceIntrinsic(short signatureAlgorithm)
    {
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.ed25519:
            return ed25519;
        case SignatureAlgorithm.ed448:
            return ed448;
        case SignatureAlgorithm.gostr34102012_256:
            return gostr34102012_256;
        case SignatureAlgorithm.gostr34102012_512:
            return gostr34102012_512;
        case SignatureAlgorithm.rsa_pss_rsae_sha256:
            return rsa_pss_rsae_sha256;
        case SignatureAlgorithm.rsa_pss_rsae_sha384:
            return rsa_pss_rsae_sha384;
        case SignatureAlgorithm.rsa_pss_rsae_sha512:
            return rsa_pss_rsae_sha512;
        case SignatureAlgorithm.rsa_pss_pss_sha256:
            return rsa_pss_pss_sha256;
        case SignatureAlgorithm.rsa_pss_pss_sha384:
            return rsa_pss_pss_sha384;
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            return rsa_pss_pss_sha512;
        case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
            return ecdsa_brainpoolP256r1tls13_sha256;
        case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
            return ecdsa_brainpoolP384r1tls13_sha384;
        case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
            return ecdsa_brainpoolP512r1tls13_sha512;
        default:
            return create(HashAlgorithm.Intrinsic, signatureAlgorithm);
        }
    }

    private static SignatureAndHashAlgorithm create(int signatureScheme)
    {
        short hashAlgorithm = SignatureScheme.getHashAlgorithm(signatureScheme);
        short signatureAlgorithm = SignatureScheme.getSignatureAlgorithm(signatureScheme);
        return create(hashAlgorithm, signatureAlgorithm);
    }

    private static SignatureAndHashAlgorithm create(short hashAlgorithm, short signatureAlgorithm)
    {
        return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
    }

    protected final short hash;
    protected final short signature;

    /**
     * @param hash      {@link HashAlgorithm}
     * @param signature {@link SignatureAlgorithm}
     */
    public SignatureAndHashAlgorithm(short hash, short signature)
    {
        /*
         * TODO]tls] The TlsUtils methods are inlined here to avoid circular static initialization
         * b/w these classes. We should refactor parts of TlsUtils into separate classes. e.g. the
         * TLS low-level encoding methods, and/or the SigAndHash registry and methods.
         */

//        if (!TlsUtils.isValidUint8(hash))
        if ((hash & 0xFF) != hash)
        {
            throw new IllegalArgumentException("'hash' should be a uint8");
        }
//        if (!TlsUtils.isValidUint8(signature))
        if ((signature & 0xFF) != signature)
        {
            throw new IllegalArgumentException("'signature' should be a uint8");
        }

        this.hash = hash;
        this.signature = signature;
    }

    /**
     * @return {@link HashAlgorithm}
     */
    public short getHash()
    {
        return hash;
    }

    /**
     * @return {@link SignatureAlgorithm}
     */
    public short getSignature()
    {
        return signature;
    }

    /**
     * Encode this {@link SignatureAndHashAlgorithm} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        TlsUtils.writeUint8(getHash(), output);
        TlsUtils.writeUint8(getSignature(), output);
    }

    /**
     * Parse a {@link SignatureAndHashAlgorithm} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link SignatureAndHashAlgorithm} object.
     * @throws IOException
     */
    public static SignatureAndHashAlgorithm parse(InputStream input)
        throws IOException
    {
        short hash = TlsUtils.readUint8(input);
        short signature = TlsUtils.readUint8(input);

        return getInstance(hash, signature);
    }

    public boolean equals(Object obj)
    {
        if (!(obj instanceof SignatureAndHashAlgorithm))
        {
            return false;
        }
        SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm)obj;
        return other.getHash() == getHash() && other.getSignature() == getSignature();
    }

    public int hashCode()
    {
        return (getHash() << 16) | getSignature();
    }

    public String toString()
    {
        return "{" + HashAlgorithm.getText(hash) + "," + SignatureAlgorithm.getText(signature) + "}";
    }
}
