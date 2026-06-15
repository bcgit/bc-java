package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
{
    private final AlgorithmIdentifier algorithmIdentifier;

    public KeyFactorySpi()
    {
        this(null);
    }

    /**
     * @param algorithmIdentifier the AlgorithmIdentifier to stamp on keys built from raw
     *                            {@link RSAPublicKeySpec} / {@link RSAPrivateKeySpec} /
     *                            {@link RSAPrivateCrtKeySpec} parameters, or null for the
     *                            default rsaEncryption identifier.
     */
    protected KeyFactorySpi(AlgorithmIdentifier algorithmIdentifier)
    {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
        if ((spec.isAssignableFrom(KeySpec.class) || spec.isAssignableFrom(RSAPublicKeySpec.class)) && key instanceof RSAPublicKey)
        {
            RSAPublicKey k = (RSAPublicKey)key;

            return new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent());
        }
        else if ((spec.isAssignableFrom(KeySpec.class) || spec.isAssignableFrom(RSAPrivateCrtKeySpec.class)) && key instanceof RSAPrivateCrtKey)
        {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey)key;

            return new RSAPrivateCrtKeySpec(
                k.getModulus(), k.getPublicExponent(),
                k.getPrivateExponent(),
                k.getPrimeP(), k.getPrimeQ(),
                k.getPrimeExponentP(), k.getPrimeExponentQ(),
                k.getCrtCoefficient());
        }
        else if ((spec.isAssignableFrom(KeySpec.class) || spec.isAssignableFrom(RSAPrivateKeySpec.class)) && key instanceof java.security.interfaces.RSAPrivateKey)
        {
            java.security.interfaces.RSAPrivateKey k = (java.security.interfaces.RSAPrivateKey)key;

            return new RSAPrivateKeySpec(k.getModulus(), k.getPrivateExponent());
        }
        else if (spec.isAssignableFrom(OpenSSHPublicKeySpec.class) && key instanceof RSAPublicKey)
        {
            try
            {
                return new OpenSSHPublicKeySpec(
                    OpenSSHPublicKeyUtil.encodePublicKey(
                        new RSAKeyParameters(
                            false,
                            ((RSAPublicKey)key).getModulus(),
                            ((RSAPublicKey)key).getPublicExponent())
                    )
                );
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException("unable to produce encoding", e);
            }
        }
        else if (spec.isAssignableFrom(OpenSSHPrivateKeySpec.class) && key instanceof RSAPrivateCrtKey)
        {
            try
            {
                return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new RSAPrivateCrtKeyParameters(
                    ((RSAPrivateCrtKey)key).getModulus(),
                    ((RSAPrivateCrtKey)key).getPublicExponent(),
                    ((RSAPrivateCrtKey)key).getPrivateExponent(),
                    ((RSAPrivateCrtKey)key).getPrimeP(),
                    ((RSAPrivateCrtKey)key).getPrimeQ(),
                    ((RSAPrivateCrtKey)key).getPrimeExponentP(),
                    ((RSAPrivateCrtKey)key).getPrimeExponentQ(),
                    ((RSAPrivateCrtKey)key).getCrtCoefficient()
                )));
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException("unable to produce encoding", e);
            }
        }

        return super.engineGetKeySpec(key, spec);
    }

    protected Key engineTranslateKey(
        Key key)
        throws InvalidKeyException
    {
        if (key instanceof RSAPublicKey)
        {
            return new BCRSAPublicKey((RSAPublicKey)key);
        }
        else if (key instanceof RSAPrivateCrtKey)
        {
            return new BCRSAPrivateCrtKey((RSAPrivateCrtKey)key);
        }
        else if (key instanceof java.security.interfaces.RSAPrivateKey)
        {
            return new BCRSAPrivateKey((java.security.interfaces.RSAPrivateKey)key);
        }

        throw new InvalidKeyException("key type unknown");
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            try
            {
                return generatePrivate(PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
            }
            catch (Exception e)
            {
                //
                // in case it's just a RSAPrivateKey object... -- openSSL produces these
                //
                try
                {
                    return new BCRSAPrivateCrtKey(
                        RSAPrivateKey.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded()));
                }
                catch (Exception ex)
                {
                    throw new ExtendedInvalidKeySpecException("unable to process key spec: " + e.toString(), e);
                }
            }
        }
        else if (keySpec instanceof RSAPrivateCrtKeySpec)
        {
            if (algorithmIdentifier != null)
            {
                RSAPrivateCrtKeySpec spec = (RSAPrivateCrtKeySpec)keySpec;

                return new BCRSAPrivateCrtKey(algorithmIdentifier, new RSAPrivateCrtKeyParameters(
                    spec.getModulus(), spec.getPublicExponent(), spec.getPrivateExponent(),
                    spec.getPrimeP(), spec.getPrimeQ(), spec.getPrimeExponentP(), spec.getPrimeExponentQ(),
                    spec.getCrtCoefficient()));
            }
            return new BCRSAPrivateCrtKey((RSAPrivateCrtKeySpec)keySpec);
        }
        else if (keySpec instanceof RSAPrivateKeySpec)
        {
            if (algorithmIdentifier != null)
            {
                RSAPrivateKeySpec spec = (RSAPrivateKeySpec)keySpec;

                return new BCRSAPrivateKey(algorithmIdentifier,
                    new RSAKeyParameters(true, spec.getModulus(), spec.getPrivateExponent()));
            }
            return new BCRSAPrivateKey((RSAPrivateKeySpec)keySpec);
        }
        else if (keySpec instanceof OpenSSHPrivateKeySpec)
        {
            OpenSSHPrivateKeySpec sshKeySpec = (OpenSSHPrivateKeySpec)keySpec;
            char[] password = sshKeySpec.getPassword();
            CipherParameters parameters;
            try
            {
                parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(
                    sshKeySpec.getEncoded(), password == null ? null : Strings.toUTF8ByteArray(password));
            }
            catch (RuntimeException e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode OpenSSH private key: " + e.getMessage(), e);
            }

            if (parameters instanceof RSAPrivateCrtKeyParameters)
            {
                return new BCRSAPrivateCrtKey((RSAPrivateCrtKeyParameters)parameters);
            }

            throw new InvalidKeySpecException("open SSH public key is not RSA private key");
        }

        throw new InvalidKeySpecException("unknown KeySpec type: " + keySpec.getClass().getName());
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof RSAPublicKeySpec)
        {
            if (algorithmIdentifier != null)
            {
                RSAPublicKeySpec spec = (RSAPublicKeySpec)keySpec;

                return new BCRSAPublicKey(algorithmIdentifier,
                    new RSAKeyParameters(false, spec.getModulus(), spec.getPublicExponent()));
            }
            return new BCRSAPublicKey((RSAPublicKeySpec)keySpec);
        }
        else if (keySpec instanceof OpenSSHPublicKeySpec)
        {

            CipherParameters parameters = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
            if (parameters instanceof RSAKeyParameters)
            {
                return new BCRSAPublicKey((RSAKeyParameters)parameters);
            }

            throw new InvalidKeySpecException("Open SSH public key is not RSA public key");

        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (RSAUtil.isRsaOid(algOid))
        {
            RSAPrivateKey rsaPrivKey = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

            if (rsaPrivKey.getCoefficient().intValue() == 0)
            {
                return new BCRSAPrivateKey(keyInfo.getPrivateKeyAlgorithm(), rsaPrivKey);
            }
            else
            {
                return new BCRSAPrivateCrtKey(keyInfo);
            }
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (RSAUtil.isRsaOid(algOid))
        {
            return new BCRSAPublicKey(keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    /**
     * KeyFactory for the "RSASSA-PSS" algorithm. Keys built from raw RSA key specs
     * ({@link RSAPublicKeySpec} / {@link RSAPrivateKeySpec} / {@link RSAPrivateCrtKeySpec})
     * are stamped with the id-RSASSA-PSS algorithm identifier (RFC 8017 A.2.3) so that the
     * resulting keys report {@code RSASSA-PSS} from {@code getAlgorithm()} and encode with the
     * correct OID, matching the keys produced by {@code KeyPairGenerator.getInstance("RSASSA-PSS")}.
     */
    public static class PSS
        extends KeyFactorySpi
    {
        public PSS()
        {
            super(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS));
        }
    }
}
