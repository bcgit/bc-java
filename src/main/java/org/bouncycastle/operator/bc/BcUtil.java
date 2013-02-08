package org.bouncycastle.operator.bc;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.operator.OperatorCreationException;

class BcUtil
{
    static Digest createDigest(AlgorithmIdentifier digAlg)
        throws OperatorCreationException
    {
        Digest dig;

        if (digAlg.getAlgorithm().equals(OIWObjectIdentifiers.idSHA1))
        {
            dig = new SHA1Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha224))
        {
            dig = new SHA224Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha256))
        {
            dig = new SHA256Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha384))
        {
            dig = new SHA384Digest();
        }
        else if (digAlg.getAlgorithm().equals(NISTObjectIdentifiers.id_sha512))
        {
            dig = new SHA512Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md5))
        {
            dig = new MD5Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md4))
        {
            dig = new MD4Digest();
        }
        else if (digAlg.getAlgorithm().equals(PKCSObjectIdentifiers.md2))
        {
            dig = new MD2Digest();
        }
        else if (digAlg.getAlgorithm().equals(CryptoProObjectIdentifiers.gostR3411))
        {
            dig = new GOST3411Digest();
        }
        else if (digAlg.getAlgorithm().equals(TeleTrusTObjectIdentifiers.ripemd128))
        {
            dig = new RIPEMD128Digest();
        }
        else if (digAlg.getAlgorithm().equals(TeleTrusTObjectIdentifiers.ripemd160))
        {
            dig = new RIPEMD160Digest();
        }
        else if (digAlg.getAlgorithm().equals(TeleTrusTObjectIdentifiers.ripemd256))
        {
            dig = new RIPEMD256Digest();
        }
        else
        {
            throw new OperatorCreationException("cannot recognise digest");
        }

        return dig;
    }
}
