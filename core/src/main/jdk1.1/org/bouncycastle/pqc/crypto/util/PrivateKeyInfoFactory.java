package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.FalconPrivateKey;
import org.bouncycastle.pqc.asn1.FalconPublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.legacy.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.util.Pack;

/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PrivateKeyInfoFactory
{
    private PrivateKeyInfoFactory()
    {
    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey) throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException
    {
        if (privateKey instanceof SPHINCSPrivateKeyParameters)
        {
            SPHINCSPrivateKeyParameters params = (SPHINCSPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256,
                new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(params.getTreeDigest())));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getKeyData()));
        }
        else if (privateKey instanceof NHPrivateKeyParameters)
        {
            NHPrivateKeyParameters params = (NHPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);

            short[] privateKeyData = params.getSecData();

            byte[] octets = new byte[privateKeyData.length * 2];
            for (int i = 0; i != privateKeyData.length; i++)
            {
                Pack.shortToLittleEndian(privateKeyData[i], octets, i * 2);
            }

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(octets));
        }
        else if (privateKey instanceof SLHDSAPrivateKeyParameters)
        {
            SLHDSAPrivateKeyParameters params = (SLHDSAPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.slhdsaOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes, params.getPublicKey());
        }
        else if (privateKey instanceof SABERPrivateKeyParameters)
        {
            SABERPrivateKeyParameters params = (SABERPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.saberOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof FalconPrivateKeyParameters)
        {
            FalconPrivateKeyParameters params = (FalconPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.falconOidLookup(params.getParameters()));

            FalconPublicKey falconPub = new FalconPublicKey(params.getPublicKey());
            FalconPrivateKey falconPriv = new FalconPrivateKey(0, params.getSpolyf(), params.getG(), params.getSpolyF(), falconPub);

            return new PrivateKeyInfo(algorithmIdentifier, falconPriv, attributes);
        }
        else if (privateKey instanceof MLKEMPrivateKeyParameters)
        {
            MLKEMPrivateKeyParameters params = (MLKEMPrivateKeyParameters)privateKey;
            
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mlkemOidLookup(params.getParameters()));

            byte[] seed = params.getSeed();
            if (seed == null)
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes);
            }
            else
            {
                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(seed), attributes);
            }
        }
        else if (privateKey instanceof MLDSAPrivateKeyParameters)
        {
            MLDSAPrivateKeyParameters params = (MLDSAPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mldsaOidLookup(params.getParameters()));

            byte[] seed = params.getSeed();
            if (seed == null)
            {
                MLDSAPublicKeyParameters pubParams = params.getPublicKeyParameters();

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes, pubParams.getEncoded());
            }
            else
            {
                MLDSAPublicKeyParameters pubParams = params.getPublicKeyParameters();

                return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getSeed()), attributes);
            }
        }
        else if (privateKey instanceof DilithiumPrivateKeyParameters)
        {
            DilithiumPrivateKeyParameters params = (DilithiumPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.dilithiumOidLookup(params.getParameters()));

            DilithiumPublicKeyParameters pubParams = params.getPublicKeyParameters();

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes, pubParams.getEncoded());
        }
        else if (privateKey instanceof BIKEPrivateKeyParameters)
        {
            BIKEPrivateKeyParameters params = (BIKEPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.bikeOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof HQCPrivateKeyParameters)
        {
            HQCPrivateKeyParameters params = (HQCPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.hqcOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
