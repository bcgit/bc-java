package org.bouncycastle.openpgp;

import java.util.Collections;
import java.util.List;

import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class ExtendedPGPSecretKey
    extends PGPSecretKey
{
    private final List<PGPExtendedKeyHeader> headers;
    private final List<PGPExtendedKeyAttribute> attributes;

    public ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, SecretKeyPacket secret, PGPPublicKey pub)
    {
        super(secret, pub);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, PGPPrivateKey privKey, PGPPublicKey pubKey, PGPDigestCalculator checksumCalculator, PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        super(privKey, pubKey, checksumCalculator, keyEncryptor);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    public ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, PGPPrivateKey privKey, PGPPublicKey pubKey, PGPDigestCalculator checksumCalculator, boolean isMasterKey, PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        super(privKey, pubKey, checksumCalculator, isMasterKey, keyEncryptor);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    public ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, int certificationLevel, PGPKeyPair keyPair, String id, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder certificationSignerBuilder, PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        super(certificationLevel, keyPair, id, hashedPcks, unhashedPcks, certificationSignerBuilder, keyEncryptor);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    public ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, PGPKeyPair masterKeyPair, PGPKeyPair keyPair, PGPDigestCalculator checksumCalculator, PGPContentSignerBuilder certificationSignerBuilder, PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        super(masterKeyPair, keyPair, checksumCalculator, certificationSignerBuilder, keyEncryptor);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    public ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, PGPKeyPair masterKeyPair, PGPKeyPair keyPair, PGPDigestCalculator checksumCalculator, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder certificationSignerBuilder, PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        super(masterKeyPair, keyPair, checksumCalculator, hashedPcks, unhashedPcks, certificationSignerBuilder, keyEncryptor);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    public ExtendedPGPSecretKey(List<PGPExtendedKeyHeader> headerList, List<PGPExtendedKeyAttribute> attributes, int certificationLevel, PGPKeyPair keyPair, String id, PGPDigestCalculator checksumCalculator, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder certificationSignerBuilder, PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        super(certificationLevel, keyPair, id, checksumCalculator, hashedPcks, unhashedPcks, certificationSignerBuilder, keyEncryptor);
        headers = Collections.unmodifiableList(headerList);
        this.attributes = Collections.unmodifiableList(attributes);
    }

    public List<PGPExtendedKeyHeader> getHeaders()
    {
        return headers;
    }

    public List<PGPExtendedKeyAttribute> getAttributes()
    {
        return attributes;
    }
}
