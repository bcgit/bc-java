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
import org.bouncycastle.pqc.crypto.mqom.MQOMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sdith.SDitHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.smaugt.SmaugTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.uov.UOVPrivateKeyParameters;
import org.bouncycastle.pqc.asn1.FalconPrivateKey;
import org.bouncycastle.pqc.asn1.FalconPublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.aimer.AIMerPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.faest.FaestPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.hawk.HawkPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.sphincsplus.SPHINCSPlusPrivateKeyParameters;
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
        else if (privateKey instanceof LMSPrivateKeyParameters)
        {
            LMSPrivateKeyParameters params = (LMSPrivateKeyParameters)privateKey;

            byte[] encoding = Composer.compose().u32str(1).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(1).bytes(params.getPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
        else if (privateKey instanceof HSSPrivateKeyParameters)
        {
            HSSPrivateKeyParameters params = (HSSPrivateKeyParameters)privateKey;

            byte[] encoding = Composer.compose().u32str(params.getL()).bytes(params).build();
            byte[] pubEncoding = Composer.compose().u32str(params.getL()).bytes(params.getPublicKey().getLMSPublicKey()).build();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
        else if (privateKey instanceof SPHINCSPlusPrivateKeyParameters)
        {
            SPHINCSPlusPrivateKeyParameters params = (SPHINCSPlusPrivateKeyParameters)privateKey;
                                                               
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.getEncoded()), attributes, params.getPublicKey());
        }
        else if (privateKey instanceof SABERPrivateKeyParameters)
        {
            SABERPrivateKeyParameters params = (SABERPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.saberOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof NTRUPrivateKeyParameters)
        {
            NTRUPrivateKeyParameters params = (NTRUPrivateKeyParameters)privateKey;

            byte[] encoding = params.getEncoded();

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntruOidLookup(params.getParameters()));

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
        else if (privateKey instanceof NTRULPRimePrivateKeyParameters)
        {
            NTRULPRimePrivateKeyParameters params = (NTRULPRimePrivateKeyParameters)privateKey;

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new DEROctetString(params.getEnca()));
            v.add(new DEROctetString(params.getPk()));
            v.add(new DEROctetString(params.getRho()));
            v.add(new DEROctetString(params.getHash()));

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntrulprimeOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DERSequence(v), attributes);
        }
        else if (privateKey instanceof SNTRUPrimePrivateKeyParameters)
        {
            SNTRUPrimePrivateKeyParameters params = (SNTRUPrimePrivateKeyParameters)privateKey;

            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new DEROctetString(params.getF()));
            v.add(new DEROctetString(params.getGinv()));
            v.add(new DEROctetString(params.getPk()));
            v.add(new DEROctetString(params.getRho()));
            v.add(new DEROctetString(params.getHash()));

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sntruprimeOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, new DERSequence(v), attributes);
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
        else if (privateKey instanceof MayoPrivateKeyParameters)
        {
            MayoPrivateKeyParameters params = (MayoPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mayoOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof SnovaPrivateKeyParameters)
        {
            SnovaPrivateKeyParameters params = (SnovaPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.snovaOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof NTRUPlusPrivateKeyParameters)
        {
            NTRUPlusPrivateKeyParameters params = (NTRUPlusPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.ntruPlusOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof AIMerPrivateKeyParameters)
        {
            AIMerPrivateKeyParameters params = (AIMerPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.aimerOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof SmaugTPrivateKeyParameters)
        {
            SmaugTPrivateKeyParameters params = (SmaugTPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.smaugTOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof FaestPrivateKeyParameters)
        {
            FaestPrivateKeyParameters params = (FaestPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.faestOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof QRUOVPrivateKeyParameters)
        {
            QRUOVPrivateKeyParameters params = (QRUOVPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.qruovOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof SQIsignPrivateKeyParameters)
        {
            SQIsignPrivateKeyParameters params = (SQIsignPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sqisignOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof HAETAEPrivateKeyParameters)
        {
            HAETAEPrivateKeyParameters params = (HAETAEPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.haetaeOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof HawkPrivateKeyParameters)
        {
            HawkPrivateKeyParameters params = (HawkPrivateKeyParameters)privateKey;
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.hawkOidLookup(params.getParameters()));
            byte[] encoding = params.getEncoded();
            return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes);
        }
        else if (privateKey instanceof MQOMPrivateKeyParameters)
        {
            MQOMPrivateKeyParameters params = (MQOMPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.mqomOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, params.getEncoded(), attributes);
        }
        else if (privateKey instanceof UOVPrivateKeyParameters)
        {
            UOVPrivateKeyParameters params = (UOVPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.uovOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, params.getEncoded(), attributes);
        }
        else if (privateKey instanceof SDitHPrivateKeyParameters)
        {
            SDitHPrivateKeyParameters params = (SDitHPrivateKeyParameters)privateKey;

            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.sdithOidLookup(params.getParameters()));

            return new PrivateKeyInfo(algorithmIdentifier, params.getEncoded(), attributes);
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }

}
