package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.operator.OperatorCreationException;

public class BcDefaultDigestProvider
    implements BcDigestProvider
{
    public static final BcDigestProvider INSTANCE = new BcDefaultDigestProvider();

    private BcDefaultDigestProvider()
    {

    }

    public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException
    {
        ASN1ObjectIdentifier algorithm = digestAlgorithmIdentifier.getAlgorithm();
        if (OIWObjectIdentifiers.idSHA1.equals(algorithm))
        {
            return new SHA1Digest();
        }
        else if (NISTObjectIdentifiers.id_sha224.equals(algorithm))
        {
            return new SHA224Digest();
        }
        else if (NISTObjectIdentifiers.id_sha256.equals(algorithm))
        {
            return new SHA256Digest();
        }
        else if (NISTObjectIdentifiers.id_sha384.equals(algorithm))
        {
            return new SHA384Digest();
        }
        else if (NISTObjectIdentifiers.id_sha512.equals(algorithm))
        {
            return new SHA512Digest();
        }
        else if (NISTObjectIdentifiers.id_sha512_224.equals(algorithm))
        {
            return new SHA512tDigest(224);
        }
        else if (NISTObjectIdentifiers.id_sha512_256.equals(algorithm))
        {
            return new SHA512tDigest(256);
        }
        else if (NISTObjectIdentifiers.id_sha3_224.equals(algorithm))
        {
            return new SHA3Digest(224);
        }
        else if (NISTObjectIdentifiers.id_sha3_256.equals(algorithm))
        {
            return new SHA3Digest(256);
        }
        else if (NISTObjectIdentifiers.id_sha3_384.equals(algorithm))
        {
            return new SHA3Digest(384);
        }
        else if (NISTObjectIdentifiers.id_sha3_512.equals(algorithm))
        {
            return new SHA3Digest(512);
        }
        else if (PKCSObjectIdentifiers.md5.equals(algorithm))
        {
            return new MD5Digest();
        }
        else if (PKCSObjectIdentifiers.md4.equals(algorithm))
        {
            return new MD4Digest();
        }
        else if (PKCSObjectIdentifiers.md2.equals(algorithm))
        {
            return new MD2Digest();
        }
        else if (CryptoProObjectIdentifiers.gostR3411.equals(algorithm))
        {
            return new GOST3411Digest();
        }
        else if (RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.equals(algorithm))
        {
            return new GOST3411_2012_256Digest();
        }
        else if (RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.equals(algorithm))
        {
            return new GOST3411_2012_512Digest();
        }
        else if (TeleTrusTObjectIdentifiers.ripemd128.equals(algorithm))
        {
            return new RIPEMD128Digest();
        }
        else if (TeleTrusTObjectIdentifiers.ripemd160.equals(algorithm))
        {
            return new RIPEMD160Digest();
        }
        else if (TeleTrusTObjectIdentifiers.ripemd256.equals(algorithm))
        {
            return new RIPEMD256Digest();
        }
        else if (GMObjectIdentifiers.sm3.equals(algorithm))
        {
            return new SM3Digest();
        }
        else if (NISTObjectIdentifiers.id_shake128.equals(algorithm))
        {
            return new SHAKEDigest(128);
        }
        else if (NISTObjectIdentifiers.id_shake256.equals(algorithm))
        {
            return new SHAKEDigest(256);
        }
        else if (NISTObjectIdentifiers.id_shake128_len.equals(algorithm)
            || NISTObjectIdentifiers.id_shake256_len.equals(algorithm))
        {
            int bitLength = NISTObjectIdentifiers.id_shake128_len.equals(algorithm) ? 128 : 256;
            int digestBitLength = ASN1Integer.getInstance(digestAlgorithmIdentifier.getParameters())
                                .getValue().intValueExact();
            return new SHAKELenDigest(bitLength, digestBitLength);
        } else {
           throw new OperatorCreationException("cannot recognise digest");
        }
    }
    
}
