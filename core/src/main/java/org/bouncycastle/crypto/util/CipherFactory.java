package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC2Parameters;

import java.io.OutputStream;

/**
 * Factory methods for creating Cipher objects and CipherOutputStreams.
 */
public class CipherFactory
{

    private static final short[] rc2Ekb = {
        0x5d, 0xbe, 0x9b, 0x8b, 0x11, 0x99, 0x6e, 0x4d, 0x59, 0xf3, 0x85, 0xa6, 0x3f, 0xb7, 0x83, 0xc5,
        0xe4, 0x73, 0x6b, 0x3a, 0x68, 0x5a, 0xc0, 0x47, 0xa0, 0x64, 0x34, 0x0c, 0xf1, 0xd0, 0x52, 0xa5,
        0xb9, 0x1e, 0x96, 0x43, 0x41, 0xd8, 0xd4, 0x2c, 0xdb, 0xf8, 0x07, 0x77, 0x2a, 0xca, 0xeb, 0xef,
        0x10, 0x1c, 0x16, 0x0d, 0x38, 0x72, 0x2f, 0x89, 0xc1, 0xf9, 0x80, 0xc4, 0x6d, 0xae, 0x30, 0x3d,
        0xce, 0x20, 0x63, 0xfe, 0xe6, 0x1a, 0xc7, 0xb8, 0x50, 0xe8, 0x24, 0x17, 0xfc, 0x25, 0x6f, 0xbb,
        0x6a, 0xa3, 0x44, 0x53, 0xd9, 0xa2, 0x01, 0xab, 0xbc, 0xb6, 0x1f, 0x98, 0xee, 0x9a, 0xa7, 0x2d,
        0x4f, 0x9e, 0x8e, 0xac, 0xe0, 0xc6, 0x49, 0x46, 0x29, 0xf4, 0x94, 0x8a, 0xaf, 0xe1, 0x5b, 0xc3,
        0xb3, 0x7b, 0x57, 0xd1, 0x7c, 0x9c, 0xed, 0x87, 0x40, 0x8c, 0xe2, 0xcb, 0x93, 0x14, 0xc9, 0x61,
        0x2e, 0xe5, 0xcc, 0xf6, 0x5e, 0xa8, 0x5c, 0xd6, 0x75, 0x8d, 0x62, 0x95, 0x58, 0x69, 0x76, 0xa1,
        0x4a, 0xb5, 0x55, 0x09, 0x78, 0x33, 0x82, 0xd7, 0xdd, 0x79, 0xf5, 0x1b, 0x0b, 0xde, 0x26, 0x21,
        0x28, 0x74, 0x04, 0x97, 0x56, 0xdf, 0x3c, 0xf0, 0x37, 0x39, 0xdc, 0xff, 0x06, 0xa4, 0xea, 0x42,
        0x08, 0xda, 0xb4, 0x71, 0xb0, 0xcf, 0x12, 0x7a, 0x4e, 0xfa, 0x6c, 0x1d, 0x84, 0x00, 0xc8, 0x7f,
        0x91, 0x45, 0xaa, 0x2b, 0xc2, 0xb1, 0x8f, 0xd5, 0xba, 0xf2, 0xad, 0x19, 0xb2, 0x67, 0x36, 0xf7,
        0x0f, 0x0a, 0x92, 0x7d, 0xe3, 0x9d, 0xe9, 0x90, 0x3e, 0x23, 0x27, 0x66, 0x13, 0xec, 0x81, 0x15,
        0xbd, 0x22, 0xbf, 0x9f, 0x7e, 0xa9, 0x51, 0x4b, 0x4c, 0xfb, 0x02, 0xd3, 0x70, 0x86, 0x31, 0xe7,
        0x3b, 0x05, 0x03, 0x54, 0x60, 0x48, 0x65, 0x18, 0xd2, 0xcd, 0x5f, 0x32, 0x88, 0x0e, 0x35, 0xfd
    };

    /**
     * Create a content cipher for encrypting bulk data.
     *
     * @param forEncryption true if the cipher is for encryption, false otherwise.
     * @param encKey the basic key to use.
     * @param encryptionAlgID identifying algorithm OID and parameters to use.
     * @return a StreamCipher or a BufferedBlockCipher depending on the algorithm.
     * @throws IllegalArgumentException
     */
    public static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws IllegalArgumentException
    {
        ASN1ObjectIdentifier encAlg = encryptionAlgID.getAlgorithm();

        if (encAlg.equals(PKCSObjectIdentifiers.rc4))
        {
            StreamCipher cipher = new RC4Engine();

            cipher.init(forEncryption, encKey);

            return cipher;
        }
        else if(encAlg.equals(NISTObjectIdentifiers.id_aes128_GCM)
            || encAlg.equals(NISTObjectIdentifiers.id_aes192_GCM)
            || encAlg.equals(NISTObjectIdentifiers.id_aes256_GCM))
        {
            AEADBlockCipher cipher = createAEADCipher(encryptionAlgID.getAlgorithm());
            GCMParameters gcmParameters = GCMParameters.getInstance(encryptionAlgID.getParameters());
            if(!(encKey instanceof KeyParameter)){
                throw new IllegalArgumentException("key data must be accessible for GCM operation") ;
            }
            AEADParameters aeadParameters = new AEADParameters((KeyParameter) encKey, gcmParameters.getIcvLen() * 8, gcmParameters.getNonce());
            cipher.init(forEncryption, aeadParameters);
            return cipher;
        }
        else
        {
            BufferedBlockCipher cipher = createCipher(encryptionAlgID.getAlgorithm());
            ASN1Primitive sParams = encryptionAlgID.getParameters().toASN1Primitive();

            if (sParams != null && !(sParams instanceof ASN1Null))
            {
                if (encAlg.equals(PKCSObjectIdentifiers.des_EDE3_CBC)
                    || encAlg.equals(AlgorithmIdentifierFactory.IDEA_CBC)
                    || encAlg.equals(NISTObjectIdentifiers.id_aes128_CBC)
                    || encAlg.equals(NISTObjectIdentifiers.id_aes192_CBC)
                    || encAlg.equals(NISTObjectIdentifiers.id_aes256_CBC)
                    || encAlg.equals(NTTObjectIdentifiers.id_camellia128_cbc)
                    || encAlg.equals(NTTObjectIdentifiers.id_camellia192_cbc)
                    || encAlg.equals(NTTObjectIdentifiers.id_camellia256_cbc)
                    || encAlg.equals(KISAObjectIdentifiers.id_seedCBC)
                    || encAlg.equals(OIWObjectIdentifiers.desCBC))
                {
                    cipher.init(forEncryption, new ParametersWithIV(encKey,
                        ASN1OctetString.getInstance(sParams).getOctets()));
                }
                else if (encAlg.equals(AlgorithmIdentifierFactory.CAST5_CBC))
                {
                    CAST5CBCParameters cbcParams = CAST5CBCParameters.getInstance(sParams);

                    cipher.init(forEncryption, new ParametersWithIV(encKey, cbcParams.getIV()));
                }
                else if (encAlg.equals(PKCSObjectIdentifiers.RC2_CBC))
                {
                    RC2CBCParameter cbcParams = RC2CBCParameter.getInstance(sParams);

                    cipher.init(forEncryption, new ParametersWithIV(new RC2Parameters(((KeyParameter)encKey).getKey(), rc2Ekb[cbcParams.getRC2ParameterVersion().intValue()]), cbcParams.getIV()));
                }
                else
                {
                    throw new IllegalArgumentException("cannot match parameters");
                }
            }
            else
            {
                if (encAlg.equals(PKCSObjectIdentifiers.des_EDE3_CBC)
                    || encAlg.equals(AlgorithmIdentifierFactory.IDEA_CBC)
                    || encAlg.equals(AlgorithmIdentifierFactory.CAST5_CBC))
                {
                    cipher.init(forEncryption, new ParametersWithIV(encKey, new byte[8]));
                }
                else
                {
                    cipher.init(forEncryption, encKey);
                }
            }

            return cipher;
        }
    }

    private static AEADBlockCipher createAEADCipher(ASN1ObjectIdentifier algorithm){
        if (NISTObjectIdentifiers.id_aes128_GCM.equals(algorithm)
                || NISTObjectIdentifiers.id_aes192_GCM.equals(algorithm)
                || NISTObjectIdentifiers.id_aes256_GCM.equals(algorithm))
        {
            return new GCMBlockCipher(new AESEngine());
        }
        else
        {
            throw new IllegalArgumentException("cannot recognise cipher: " + algorithm);
        }
    }

    private static BufferedBlockCipher createCipher(ASN1ObjectIdentifier algorithm)
        throws IllegalArgumentException
    {
        BlockCipher cipher;

        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm)
            || NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new AESEngine());
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new DESedeEngine());
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new DESEngine());
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new RC2Engine());
        }
        else if (MiscObjectIdentifiers.cast5CBC.equals(algorithm))
        {
            cipher = new CBCBlockCipher(new CAST5Engine());
        }
        else
        {
            throw new IllegalArgumentException("cannot recognise cipher: " + algorithm);
        }

        return new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    }

    /**
     * Return a new CipherOutputStream based on the passed in cipher.
     *
     * @param dOut the output stream to write the processed data to.
     * @param cipher the cipher to use.
     * @return a BC CipherOutputStream using the cipher and writing to dOut.
     */
    public static CipherOutputStream createOutputStream(OutputStream dOut, Object cipher)
    {
        if (cipher instanceof BufferedBlockCipher)
        {
            return new CipherOutputStream(dOut, (BufferedBlockCipher)cipher);
        }
        if (cipher instanceof StreamCipher)
        {
            return new CipherOutputStream(dOut, (StreamCipher)cipher);
        }
        if (cipher instanceof AEADBlockCipher)
        {
            return new CipherOutputStream(dOut, (AEADBlockCipher)cipher);
        }
        throw new IllegalArgumentException("unknown cipher object: " + cipher);
    }

}
