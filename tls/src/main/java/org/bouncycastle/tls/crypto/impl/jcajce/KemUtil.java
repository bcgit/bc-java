package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

class KemUtil
{
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

    static KeyFactory getKeyFactory(JcaTlsCrypto crypto, String kemName)
    
    {
        try
        {
            return crypto.getHelper().createKeyFactory(kemName);
        }
        catch (AssertionError e)
        {
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static KeyGenerator getKeyGenerator(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            return crypto.getHelper().createKeyGenerator(kemName);
        }
        catch (AssertionError e)
        {
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static KeyPairGenerator getKeyPairGenerator(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("ML-KEM");
            keyPairGenerator.initialize(MLKEMParameterSpec.fromName(kemName), crypto.getSecureRandom());
            return keyPairGenerator;
        }
        catch (AssertionError e)
        {
        }
        catch (Exception e)
        {
        }

        return null;
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        return kemName != null
            && getKeyFactory(crypto, kemName) != null
            && getKeyGenerator(crypto, kemName) != null
            && getKeyPairGenerator(crypto, kemName) != null;
    }

    private static X509EncodedKeySpec createX509EncodedKeySpec(ASN1ObjectIdentifier oid, byte[] encoding)
        throws IOException
    {
        AlgorithmIdentifier algID = new AlgorithmIdentifier(oid);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, encoding);
        return new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER));
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
}
