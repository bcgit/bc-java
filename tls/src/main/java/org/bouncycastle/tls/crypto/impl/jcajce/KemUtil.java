package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

class KemUtil
{
    private static KeyPairGenerator createKeyPairGenerator(JcaTlsCrypto crypto, String kemName)
        throws GeneralSecurityException
    {
        // TODO How to pass only the SecureRandom to initialize if we use the full name in the getInstance?
//        KeyPairGenerator keyPairGenerator = KemUtil.getKeyPairGenerator(crypto, kemName);
//        keyPairGenerator.initialize((AlgorithmParameterSpec)null, crypto.getSecureRandom());
        KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("ML-KEM");
        keyPairGenerator.initialize(MLKEMParameterSpec.fromName(kemName), crypto.getSecureRandom());
        return keyPairGenerator;
    }

    private static X509EncodedKeySpec createX509EncodedKeySpec(ASN1ObjectIdentifier oid, byte[] encoding)
        throws IOException
    {
        AlgorithmIdentifier algID = new AlgorithmIdentifier(oid);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, encoding);
        return new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER));
    }

    static JceTlsSecret decapsulate(JcaTlsCrypto crypto, String kemName, PrivateKey privateKey, byte[] ciphertext)
    {
        try
        {
            KeyGenerator keyGenerator = crypto.getHelper().createKeyGenerator(kemName);
            keyGenerator.init(new KEMExtractSpec.Builder(privateKey, ciphertext, "DEF", 256).withNoKdf().build());
            SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation)keyGenerator.generateKey();
            return crypto.adoptLocalSecret(secEnc.getEncoded());
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    static SecretKeyWithEncapsulation encapsulate(JcaTlsCrypto crypto, String kemName, PublicKey publicKey)
    {
        try
        {
            KeyGenerator keyGenerator = crypto.getHelper().createKeyGenerator(kemName);
            keyGenerator.init(new KEMGenerateSpec.Builder(publicKey, "DEF", 256).withNoKdf().build());
            return (SecretKeyWithEncapsulation)keyGenerator.generateKey();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    static PublicKey decodePublicKey(JcaTlsCrypto crypto, String kemName, byte[] encoding) throws TlsFatalAlert
    {
        try
        {
            KeyFactory kf = crypto.getHelper().createKeyFactory(kemName);

            // More efficient BC-specific method
            if (kf.getProvider() instanceof BouncyCastleProvider)
            {
                try
                {
                    // TODO Add RawEncodedKeySpec support to BC?

                    MLKEMParameterSpec params = MLKEMParameterSpec.fromName(kemName);
                    MLKEMPublicKeySpec keySpec = new MLKEMPublicKeySpec(params, encoding);
                    return kf.generatePublic(keySpec);
                }
                catch (Exception e)
                {
                    // Fallback to X.509
                }
            }

            EncodedKeySpec keySpec = createX509EncodedKeySpec(getAlgorithmOID(kemName), encoding);
            return kf.generatePublic(keySpec);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    static byte[] encodePublicKey(PublicKey publicKey) throws TlsFatalAlert
    {
        // More efficient BC-specific method
        if (publicKey instanceof MLKEMPublicKey)
        {
            return ((MLKEMPublicKey)publicKey).getPublicData();
        }

        if (!"X.509".equals(publicKey.getFormat()))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "Public key format unrecognized");
        }

        try
        {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            return spki.getPublicKeyData().getOctets();
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    static KeyPair generateKeyPair(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            return createKeyPairGenerator(crypto, kemName).generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    private static ASN1ObjectIdentifier getAlgorithmOID(String kemName)
    {
        if ("ML-KEM-512".equalsIgnoreCase(kemName))
        {
            return NISTObjectIdentifiers.id_alg_ml_kem_512;
        }
        if ("ML-KEM-768".equalsIgnoreCase(kemName))
        {
            return NISTObjectIdentifiers.id_alg_ml_kem_768;
        }
        if ("ML-KEM-1024".equalsIgnoreCase(kemName))
        {
            return NISTObjectIdentifiers.id_alg_ml_kem_1024;
        }

        throw new IllegalArgumentException("unknown kem name " + kemName);
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        if (kemName != null)
        {
            try
            {
                JcaJceHelper helper = crypto.getHelper();
                createKeyPairGenerator(crypto, kemName);
                helper.createKeyFactory(kemName);
                helper.createKeyGenerator(kemName);
                return true;
            }
            catch (AssertionError e)
            {
            }
            catch (Exception e)
            {
            }
        }
        return false;
    }
}
