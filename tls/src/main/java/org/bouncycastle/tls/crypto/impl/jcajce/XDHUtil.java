package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

class XDHUtil
{
    static PublicKey decodePublicKey(JcaTlsCrypto crypto, String keyFactoryAlgorithm,
        ASN1ObjectIdentifier algorithmOID, byte[] encoding) throws TlsFatalAlert
    {
        try
        {
            KeyFactory kf = crypto.getHelper().createKeyFactory(keyFactoryAlgorithm);

            // More efficient BC-specific method
            if (kf.getProvider() instanceof BouncyCastleProvider)
            {
                try
                {
                    EncodedKeySpec keySpec = new RawEncodedKeySpec(encoding);
                    return kf.generatePublic(keySpec);
                }
                catch (Exception e)
                {
                    // Fallback to X.509
                }
            }

            EncodedKeySpec keySpec = createX509EncodedKeySpec(algorithmOID, encoding);
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
        if (publicKey instanceof XDHPublicKey)
        {
            return ((XDHPublicKey)publicKey).getUEncoding();
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

    private static X509EncodedKeySpec createX509EncodedKeySpec(ASN1ObjectIdentifier oid, byte[] encoding)
        throws IOException
    {
        AlgorithmIdentifier algID = new AlgorithmIdentifier(oid);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, encoding);
        return new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER));
    }
}
