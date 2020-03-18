package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    static final byte[] x448Prefix = Hex.decode("3042300506032b656f033900");
    static final byte[] x25519Prefix = Hex.decode("302a300506032b656e032100");
    static final byte[] Ed448Prefix = Hex.decode("3043300506032b6571033a00");
    static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");

    private static final byte x448_type = 0x6f;
    private static final byte x25519_type = 0x6e;
    private static final byte Ed448_type = 0x71;
    private static final byte Ed25519_type = 0x70;

    String algorithm;
    private final boolean isXdh;
    private final int specificBase;

    public KeyFactorySpi(
        String algorithm,
        boolean isXdh,
        int specificBase)
    {
        this.algorithm = algorithm;
        this.isXdh = isXdh;
        this.specificBase = specificBase;
    }

    protected Key engineTranslateKey(
        Key key)
        throws InvalidKeyException
    {
        throw new InvalidKeyException("key type unknown");
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(OpenSSHPrivateKeySpec.class) && key instanceof BCEdDSAPrivateKey)
        {
            try
            {
                //
                // The DEROctetString at element 2 is an encoded DEROctetString with the private key value
                // within it.
                //

                ASN1Sequence seq = ASN1Sequence.getInstance(key.getEncoded());
                DEROctetString val = (DEROctetString)seq.getObjectAt(2);
                ASN1InputStream in = new ASN1InputStream(val.getOctets());

                return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new Ed25519PrivateKeyParameters(ASN1OctetString.getInstance(in.readObject()).getOctets(), 0)));
            }
            catch (IOException ex)
            {
                throw new InvalidKeySpecException(ex.getMessage(), ex.getCause());
            }

        }
        else if (spec.isAssignableFrom(OpenSSHPublicKeySpec.class) && key instanceof BCEdDSAPublicKey)
        {
            try
            {
                return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new Ed25519PublicKeyParameters(key.getEncoded(), Ed25519Prefix.length)));
            }
            catch (IOException ex)
            {
                throw new InvalidKeySpecException(ex.getMessage(), ex.getCause());
            }
        }
        if (spec.isAssignableFrom(org.bouncycastle.jce.spec.OpenSSHPrivateKeySpec.class) && key instanceof BCEdDSAPrivateKey)
        {
            try
            {
                //
                // The DEROctetString at element 2 is an encoded DEROctetString with the private key value
                // within it.
                //

                ASN1Sequence seq = ASN1Sequence.getInstance(key.getEncoded());
                DEROctetString val = (DEROctetString)seq.getObjectAt(2);
                ASN1InputStream in = new ASN1InputStream(val.getOctets());

                return new org.bouncycastle.jce.spec.OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new Ed25519PrivateKeyParameters(ASN1OctetString.getInstance(in.readObject()).getOctets(), 0)));
            }
            catch (IOException ex)
            {
                throw new InvalidKeySpecException(ex.getMessage(), ex.getCause());
            }

        }
        else if (spec.isAssignableFrom(org.bouncycastle.jce.spec.OpenSSHPublicKeySpec.class) && key instanceof BCEdDSAPublicKey)
        {
            try
            {
                return new org.bouncycastle.jce.spec.OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new Ed25519PublicKeyParameters(key.getEncoded(), Ed25519Prefix.length)));
            }
            catch (IOException ex)
            {
                throw new InvalidKeySpecException(ex.getMessage(), ex.getCause());
            }
        }

        return super.engineGetKeySpec(key, spec);
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof OpenSSHPrivateKeySpec)
        {
            CipherParameters parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());
            if (parameters instanceof Ed25519PrivateKeyParameters)
            {
                return new BCEdDSAPrivateKey((Ed25519PrivateKeyParameters)parameters);
            }
            throw new IllegalStateException("openssh private key not Ed25519 private key");
        }

        return super.engineGeneratePrivate(keySpec);
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] enc = ((X509EncodedKeySpec)keySpec).getEncoded();
            // optimise if we can
            if ((specificBase == 0 || specificBase == enc[8]))
            {
                // watch out for badly placed DER NULL - the default X509Cert will add these!
                if (enc[9] == 0x05 && enc[10] == 0x00)
                {
                    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(enc);

                    keyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(keyInfo.getAlgorithm().getAlgorithm()), keyInfo.getPublicKeyData().getBytes());

                    try
                    {
                        enc = keyInfo.getEncoded(ASN1Encoding.DER);
                    }
                    catch (IOException e)
                    {
                        throw new InvalidKeySpecException("attempt to reconstruct key failed: " + e.getMessage());
                    }
                }

                switch (enc[8])
                {
                case x448_type:
                    return new BC11XDHPublicKey(x448Prefix, enc);
                case x25519_type:
                    return new BC11XDHPublicKey(x25519Prefix, enc);
                case Ed448_type:
                    return new BCEdDSAPublicKey(Ed448Prefix, enc);
                case Ed25519_type:
                    return new BCEdDSAPublicKey(Ed25519Prefix, enc);
                default:
                    return super.engineGeneratePublic(keySpec);
                }
            }
        }
        else if (keySpec instanceof OpenSSHPublicKeySpec)
        {
            CipherParameters parameters = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
            if (parameters instanceof Ed25519PublicKeyParameters)
            {
                return new BCEdDSAPublicKey(new byte[0], ((Ed25519PublicKeyParameters)parameters).getEncoded());
            }

            throw new IllegalStateException("openssh public key not Ed25519 public key");
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (isXdh)
        {
            if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
            {
                return new BC11XDHPrivateKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
            {
                return new BC11XDHPrivateKey(keyInfo);
            }
        }
        else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new BCEdDSAPrivateKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                return new BCEdDSAPrivateKey(keyInfo);
            }
        }

        throw new IOException("algorithm identifier " + algOid + " in key not recognized");
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (isXdh)
        {
            if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
            {
                return new BC11XDHPublicKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
            {
                return new BC11XDHPublicKey(keyInfo);
            }
        }
        else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new BCEdDSAPublicKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                return new BCEdDSAPublicKey(keyInfo);
            }
        }

        throw new IOException("algorithm identifier " + algOid + " in key not recognized");
    }

    public static class XDH
        extends KeyFactorySpi
    {
        public XDH()
        {
            super("XDH", true, 0);
        }
    }

    public static class X448
        extends KeyFactorySpi
    {
        public X448()
        {
            super("X448", true, x448_type);
        }
    }

    public static class X25519
        extends KeyFactorySpi
    {
        public X25519()
        {
            super("X25519", true, x25519_type);
        }
    }

    public static class EdDSA
        extends KeyFactorySpi
    {
        public EdDSA()
        {
            super("EdDSA", false, 0);
        }
    }

    public static class Ed448
        extends KeyFactorySpi
    {
        public Ed448()
        {
            super("Ed448", false, Ed448_type);
        }
    }

    public static class Ed25519
        extends KeyFactorySpi
    {
        public Ed25519()
        {
            super("Ed25519", false, Ed25519_type);
        }
    }
}