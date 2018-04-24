package org.bouncycastle.operator.bc;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
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
    private static final Map lookup = createTable();

    private static Map createTable()
    {
        Map table = new HashMap();

        table.put(OIWObjectIdentifiers.idSHA1, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA1Digest();
            }
        });
        table.put(NISTObjectIdentifiers.id_sha224, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA224Digest();
            }
        });
        table.put(NISTObjectIdentifiers.id_sha256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA256Digest();
            }
        });
        table.put(NISTObjectIdentifiers.id_sha384, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA384Digest();
            }
        });
        table.put(NISTObjectIdentifiers.id_sha512, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA512Digest();
            }
        });
        table.put(NISTObjectIdentifiers.id_sha3_224, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA3Digest(224);
            }
        });
        table.put(NISTObjectIdentifiers.id_sha3_256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA3Digest(256);
            }
        });
        table.put(NISTObjectIdentifiers.id_sha3_384, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA3Digest(384);
            }
        });
        table.put(NISTObjectIdentifiers.id_sha3_512, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new SHA3Digest(512);
            }
        });
        table.put(PKCSObjectIdentifiers.md5, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new MD5Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.md4, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new MD4Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.md2, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new MD2Digest();
            }
        });
        table.put(CryptoProObjectIdentifiers.gostR3411, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new GOST3411Digest();
            }
        });
        table.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new GOST3411_2012_256Digest();
            }
        });
        table.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new GOST3411_2012_512Digest();
            }
        });
        table.put(TeleTrusTObjectIdentifiers.ripemd128, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new RIPEMD128Digest();
            }
        });
        table.put(TeleTrusTObjectIdentifiers.ripemd160, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new RIPEMD160Digest();
            }
        });
        table.put(TeleTrusTObjectIdentifiers.ripemd256, new BcDigestProvider()
        {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
            {
                return new RIPEMD256Digest();
            }
        });

        return Collections.unmodifiableMap(table);
    }

    public static final BcDigestProvider INSTANCE = new BcDefaultDigestProvider();

    private BcDefaultDigestProvider()
    {

    }

    public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException
    {
        BcDigestProvider extProv = (BcDigestProvider)lookup.get(digestAlgorithmIdentifier.getAlgorithm());

        if (extProv == null)
        {
            throw new OperatorCreationException("cannot recognise digest");
        }

        return extProv.get(digestAlgorithmIdentifier);
    }
}
