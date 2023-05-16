package org.bouncycastle.pqc.crypto.lms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * LMS digest utils provides oid mapping to provider digest name.
 */
class DigestUtil
{
    private static Map<String, ASN1ObjectIdentifier> nameToOid = new HashMap<String, ASN1ObjectIdentifier>();
    private static Map<ASN1ObjectIdentifier, String> oidToName = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        nameToOid.put("SHA-256", NISTObjectIdentifiers.id_sha256);
        nameToOid.put("SHA-512", NISTObjectIdentifiers.id_sha512);
        nameToOid.put("SHAKE128", NISTObjectIdentifiers.id_shake128);
        nameToOid.put("SHAKE256", NISTObjectIdentifiers.id_shake256);

        oidToName.put(NISTObjectIdentifiers.id_sha256, "SHA-256");
        oidToName.put(NISTObjectIdentifiers.id_sha512, "SHA-512");
        oidToName.put(NISTObjectIdentifiers.id_shake128, "SHAKE128");
        oidToName.put(NISTObjectIdentifiers.id_shake256, "SHAKE256");
    }

    static Digest getDigest(LMOtsParameters otsParameters)
    {
        return createDigest(otsParameters.getDigestOID(), otsParameters.getN());
    }

    static Digest getDigest(LMSigParameters lmSigParameters)
    {
        return createDigest(lmSigParameters.getDigestOID(), lmSigParameters.getM());
    }

    private static Digest createDigest(ASN1ObjectIdentifier digOid, int digLen)
    {
        Digest dig = createDigest(digOid);
        if (digOid.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return new WrapperDigest(dig, digLen);
        }
        if (digLen == 24)
        {
            return new WrapperDigest(dig, digLen);
        }
        return dig;
    }

    private static Digest createDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256_len))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }

    static class WrapperDigest
        implements Digest
    {

        private final Digest dig;
        private final int length;

        WrapperDigest(Digest dig, int length)
        {
            this.dig = dig;
            this.length = length;
        }

        @Override
        public String getAlgorithmName()
        {
            return dig.getAlgorithmName() + "/" + length * 8;
        }

        @Override
        public int getDigestSize()
        {
            return length;
        }

        @Override
        public void update(byte in)
        {
             dig.update(in);
        }

        @Override
        public void update(byte[] in, int inOff, int len)
        {
            dig.update(in, inOff, len);
        }

        @Override
        public int doFinal(byte[] out, int outOff)
        {
            byte[] digOut = new byte[dig.getDigestSize()];

            dig.doFinal(digOut, 0);

            System.arraycopy(digOut, 0, out, outOff, length);
            return length;
        }

        @Override
        public void reset()
        {
            dig.reset();
        }
    }
}
