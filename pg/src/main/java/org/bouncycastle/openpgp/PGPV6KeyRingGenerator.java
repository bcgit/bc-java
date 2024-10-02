package org.bouncycastle.openpgp;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class PGPV6KeyRingGenerator
{
    public PGPV6KeyRingGenerator(
            PGPKeyPair primaryKey,
            PGPSignatureSubpacketVector hashedPcks,
            PGPSignatureSubpacketVector unhashedPcks,
            PGPContentSignerBuilder keySignerBuilder,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
    {

    }

    public PGPV6KeyRingGenerator(
            PGPSecretKeyRing originalSecretRing,
            PBESecretKeyDecryptor secretKeyDecryptor,
            PGPDigestCalculator checksumCalculator,
            PGPContentSignerBuilder keySignerBuilder,
            PBESecretKeyEncryptor keyEncryptor)
            throws PGPException
    {

    }
}
