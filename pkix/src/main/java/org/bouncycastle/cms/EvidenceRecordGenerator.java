package org.bouncycastle.cms;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.ByteArrayComparator;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Generator for Version 1 EvidenceRecords.
 * <pre>
 * EvidenceRecord ::= SEQUENCE {
 *      version                   INTEGER { v1(1) } ,
 *      digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
 *      cryptoInfos               [Ø] CryptoInfos OPTIONAL,
 *      encryptionInfo            [1] EncryptionInfo OPTIONAL,
 *      archiveTimeStampSequence  ArchiveTimeStampSequence
 *      }
 * </pre>
 *
 * <p>
 * This generator must be used the following way:
 * <ol>
 * <li>Instantiate it, passing an {@link AlgorithmIdentifier} as parameter to the static
 * getInstance() method.</li>
 * <li>Set the {@link List} of {@link DataGroup} instances for which the generator will build
 * {@link EvidenceRecord} instances, using the setDataGroups() method.</li>
 * <li>Call the getRootHash() method, then request a TimeStampToken on the obtained hash.</li>
 * <li>Set the TimeStamp for the generator, using the setTimeStamp() method and passing the
 * {@link ContentInfo} retrieved from the TimeStampToken obtained at the previous step.</li>
 * <li>Call the generate() method.</li>
 * </ol>
 * </p>
 */

public class EvidenceRecordGenerator
{

    private AlgorithmIdentifier         algId;
    private MessageDigest               md;
    private int                         depth;
    private byte[]                      rootHash;
    private ContentInfo                 timestamp;
    private List<DataGroup>             dataGroups;
    private List<ASN1EncodableVector>   reducedHashtrees = new ArrayList<> ();
    private ASN1TaggedObject            reducedHashtreeForRenewal;

    public static EvidenceRecordGenerator getInstance(final AlgorithmIdentifier algId)
        throws NoSuchAlgorithmException
    {
        final MessageDigest md = MessageDigest.getInstance(algId.getAlgorithm().getId());
        return new EvidenceRecordGenerator(algId, md);
    }

    private EvidenceRecordGenerator(final AlgorithmIdentifier algId,
        final MessageDigest md)
    {
        this.algId = algId;
        this.md = md;
    }

    /**
     * Generates a {@link List} of {@link EvidenceRecord} instances for the various
     * {@link DataGroup} instances that have been specified.
     *
     * @return a {@link List} of {@link EvidenceRecord} instances.
     */
    public List<EvidenceRecord> generate()
    {
        if (timestamp == null)
        {
            throw new IllegalArgumentException("timestamp has not been provided");
        }

        final List<EvidenceRecord> records = new ArrayList<> ();
        final ASN1EncodableVector algVector = new ASN1EncodableVector();
        algVector.add(algId);
        final ASN1Sequence algos = new DERSequence(algVector);

        if (reducedHashtrees.size() == 0)
        {
            //A single data group was provided, no need to build partial hash trees
            final ArchiveTimeStamp archiveTimeStamp = ArchiveTimeStamp.getInstance(timestamp);
            final ArchiveTimeStampChain archiveTimeStampChain = ArchiveTimeStampChain
                .getInstance(archiveTimeStamp);

            records.add(new EvidenceRecord(algos, null, null,
                ArchiveTimeStampSequence.getInstance(archiveTimeStampChain)));

            return records;
        }
        else if (reducedHashtrees.size() == dataGroups.size())
        {
            final Iterator<ASN1EncodableVector> iterator = reducedHashtrees.iterator();

            buildEvidenceRecords(records, algos, iterator);
            return records;
        }

        throw new IllegalArgumentException("size of reducedHashtrees is incorrect");
    }

    /**
     * Actually builds the {@link EvidenceRecord}s
     *
     * @param records the {@link List} to which the {@link EvidenceRecord}s must be added
     * @param algos the sequence of digest algorithms to include within the {@link EvidenceRecord}
     * @param iterator an iterator over the set of reduced hash trees linked to the
     * {@link EvidenceRecord} to build.
     */
    private void buildEvidenceRecords(List<EvidenceRecord> records,
        ASN1Sequence algos,
        Iterator<ASN1EncodableVector> iterator)
    {
        while (iterator.hasNext())
        {
            ASN1EncodableVector rht = iterator.next();

            //Reduced hash trees whose size is not the same as the tree depth are rejected (i.e.
            //reduced hash trees that would be associated to a random hash value)
            if (rht.size() == depth)
            {
                final ASN1Sequence sequence = new DERSequence(rht);
                final DERTaggedObject reducedHashtree = new DERTaggedObject(false, 2, sequence);
                final ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(algId,
                    reducedHashtree, timestamp);
                final ArchiveTimeStampChain archiveTimeStampChain = ArchiveTimeStampChain
                    .getInstance(archiveTimeStamp);

                records.add(new EvidenceRecord(algos, null, null,
                    ArchiveTimeStampSequence.getInstance(archiveTimeStampChain)));
            }
        }
    }

    /**
     * Sets the timestamp token to the {@link EvidenceRecord} that were generated.
     *
     * @param digests defines the number of data groups that are covered by the set of
     * {@link EvidenceRecord}s.
     * @return a {@link List} of {@link EvidenceRecord}.
     */
    public List<EvidenceRecord> generate(final int digests) {
        if (timestamp == null)
        {
            throw new IllegalArgumentException("timestamp has not been provided");
        }

        final List<EvidenceRecord> records = new ArrayList<> ();
        final ASN1EncodableVector algVector = new ASN1EncodableVector();
        algVector.add(algId);
        final ASN1Sequence algos = new DERSequence(algVector);

        if (reducedHashtrees.size() == 0)
        {
            //A single digest was provided, no need to build partial hash trees
            final ArchiveTimeStamp archiveTimeStamp = ArchiveTimeStamp.getInstance(timestamp);
            final ArchiveTimeStampChain archiveTimeStampChain = ArchiveTimeStampChain
                .getInstance(archiveTimeStamp);

            records.add(new EvidenceRecord(algos, null, null,
                ArchiveTimeStampSequence.getInstance(archiveTimeStampChain)));

            return records;
        }
        else if (reducedHashtrees.size() == digests)
        {
            final Iterator<ASN1EncodableVector> iterator = reducedHashtrees.iterator();

            buildEvidenceRecords(records, algos, iterator);
            return records;
        }

        throw new IllegalArgumentException("size of reducedHashtrees is incorrect");
    }

    /**
     * Computes the root hash of the Merkle Tree built over a provided set of digests.
     *
     * @param digests the digests over which the Merkle Tree must be generated.
     * @return a root hash, as a byte array.
     */
    public byte[] getRootHash(final List<byte[]> digests)
    {
        if (digests.size() == 1)
        {
            rootHash = digests.get(0);
        }
        else if (rootHash == null && digests != null && digests.size() > 1)
        {
            rootHash = buildMerkleTree(digests);
        }
        return rootHash;
    }

    /**
     * Sets the {@link List} of {@link DataGroup} instances for which {@link EvidenceRecord}
     * instances will be generated.
     *
     * @param dataGroups
     */
    public void setDataGroups (final List<DataGroup> dataGroups)
    {
        this.dataGroups = dataGroups;
        reducedHashtrees.removeAll(reducedHashtrees);
    }

  /**
     * Builds a Merkle Tree over a provided set of digests.
     *
     * @param digests a {@link List} of digests over which a Merkle Tree must be generated.
     * @return the root hash of the Merkle Tree, as a byte array.
     */
    private byte[] buildMerkleTree(final List<byte[]> digests)
    {
        depth = 1;

        final TreeMap<byte[], Object> merkleTree = new TreeMap(new ByteArrayComparator
            ());
        final List<byte []> randomHashes = new ArrayList();
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(new byte[256]);

        for (final byte[] digest : digests)
        {
            merkleTree.put(digest, digest);
        }

        while ((merkleTree.size() & -merkleTree.size()) != merkleTree.size()) //pow 2 check
        {
            byte[] randBytes = secureRandom.generateSeed(md.getDigestLength());
            merkleTree.put(randBytes, randBytes);
            randomHashes.add(randBytes);
        }

        ArrayList<byte[]> leaves = new ArrayList(merkleTree.keySet());

        for (int i = 0; i < leaves.size(); i++)
        {
            final byte[] leaf = leaves.get(i);

            if (! randomHashes.contains(leaf) && i < leaves.size())
            {
                final ASN1EncodableVector reducedHashTree = new ASN1EncodableVector();
                final ASN1EncodableVector vector = new ASN1EncodableVector();
                //leaf is at even position and not last in list, i.e. first node in a pair:
                if (i % 2 == 0 && i < leaves.size())
                {
                    vector.add(new DEROctetString(leaf));
                    vector.add(new DEROctetString(leaves.get(i + 1)));
                }
                //leaf is at odd position and not last in list, i.e. second node in a pair:
                else if (i % 2 != 0 && i < leaves.size())
                {
                    vector.add(new DEROctetString(leaves.get(i - 1)));
                    vector.add(new DEROctetString(leaf));
                }
                reducedHashTree.add(PartialHashtree.getInstance(vector));
                reducedHashtrees.add(reducedHashTree);
            }
        }

        return computeNextLevel(leaves);
    }

    /**
     * Recursively compute the hashes for the next tree level, until the root hash is reached.
     * The list of reduced hash trees is updated at each recursive call.
     *
     * @param leaves the leaves below the next tree level
     * @return the root hash of the Merkle tree
     */
    private byte[] computeNextLevel (final ArrayList<byte[]> leaves) {

        if (leaves.size() == 1)
        {
            return leaves.get(0);
        }

        TreeSet<byte[]> level = new TreeSet(new ByteArrayComparator());

        for (int i = 0; i < leaves.size() - 1; i+=2)
        {
            byte[] node = md.digest(
                ByteUtils.concatenate(leaves.get(i), leaves.get(i + 1)));

            level.add(node);
        }

        if (level.size() > 1)
        {
            addLevel(level);
            depth++;
            return computeNextLevel(new ArrayList<byte[]> (level));
        }

        return level.first();
    }

    /**
     * Adds a tree level to the list of reduced hash trees.
     *
     * @param level the new tree level
     */
    private void addLevel(final TreeSet<byte[]> level)
    {
        int pos = 0;
        Iterator<byte[]> iterator = level.iterator();

        while (iterator.hasNext())
        {
            final byte[] hash = iterator.next();
            int startIndex, endIndex;

            if (pos % 2 == 0)
            {
                startIndex = (int) ((pos + 1) * Math.pow(2, depth));
            }
            else
            {
                startIndex = (int) ((pos - 1) * Math.pow(2, depth));
            }

            endIndex = startIndex + (int) Math.pow(2, depth);

            for (int i = startIndex ; i != endIndex; i++)
            {
                if (i < reducedHashtrees.size())
                {
                    reducedHashtrees.get(i).add(PartialHashtree.getInstance(
                        new DERSequence(new DEROctetString(hash))));
                }
            }
            pos++;
        }
    }

    /**
     * Builds a {@link PartialHashtree} from a sorted set of hashes.
     *
     * @param set the sorted set of hashes to convert to a PartialHashtree.
     * @return a PartialHashtree instance.
     */
    private PartialHashtree buildPartialHashtree(final TreeSet<byte[]> set)
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();

        for (final byte[] value : set) {
            final DEROctetString hash = new DEROctetString(value);
            vector.add(hash);
        }

        return PartialHashtree.getInstance(vector);
    }

    /**
     * Generates a {@link PartialHashtree} over a single hash.
     *
     * @param hash the hash, as a byte array.
     * @return a {@link PartialHashtree} instance that includes the provided hash.
     */
    private PartialHashtree buildPartialHashtree(final byte[] hash)
    {
        return PartialHashtree.getInstance(new DERSequence(new DEROctetString(hash)));
    }

    private ArchiveTimeStampSequence getArchiveTimestampSequenceFromEvidenceRecord(
        final EvidenceRecord evidenceRecord)
    {
        ASN1Sequence primitive = ASN1Sequence.getInstance(evidenceRecord.toASN1Primitive());

        for (int i = 0; i != primitive.size(); i++)
        {
            if (primitive.getObjectAt(i) instanceof ArchiveTimeStampSequence)
            {
                return (ArchiveTimeStampSequence) primitive.getObjectAt(i);
            }
        }

        return null;
    }

    /**
     * Sets the TimeStamp token to embed into the {@link EvidenceRecord} instance.
     *
     * @param timeStamp the Timestamp token, provided as a {@link TimeStampToken} object.
     */
    public void setTimeStamp(final TimeStampToken timeStamp)
    {
       this.timestamp = ContentInfo.getInstance(timeStamp.toCMSSignedData().toASN1Structure());
    }

    /**
     * Sets the TimeStamp token to embed into the {@link EvidenceRecord} instance.
     *
     * @param timestamp the Timestamp token, provided as a {@link ContentInfo} object.
     */
    public void setTimeStamp (final ContentInfo timestamp)
    {
        this.timestamp = timestamp;
    }

    /**
     *
     * Computes the digest of the last ArchiveTimeStamp of the last ArchiveTimeStampChain, using
     * the same digest algorithm as the last generated ArchiveTimeStamp.
     *
     * @param record the {@link EvidenceRecord} instance for which timestamp renewal is required.
     */
    public byte[] prepareTimeStampRenewal(final EvidenceRecord record)
        throws IOException, NoSuchAlgorithmException {

        final ArchiveTimeStampSequence archiveTimeStampSequence =
            record.getArchiveTimeStampSequence();
        ASN1Sequence archiveTimeStampChains = archiveTimeStampSequence.getArchiveTimeStampChains();

        if (archiveTimeStampChains.size() < 1)
        {
            throw new IllegalArgumentException("there is no archive timestamp chain archive "
                + "timestamp sequence");
        }

        ArchiveTimeStampChain archiveTimeStampChain = ArchiveTimeStampChain
            .getInstance(archiveTimeStampChains
                .getObjectAt(archiveTimeStampChains.size() - 1));

        ASN1Sequence archiveTimestamps = ASN1Sequence.getInstance(archiveTimeStampChain
            .getArchiveTimestamps());

        if (archiveTimestamps.size() < 1)
        {
            throw new IllegalArgumentException("there is no archive timestamp in "
                + "archivetimestamp chain");
        }

        final ArchiveTimeStamp lastArchiveTimeStamp = ArchiveTimeStamp
            .getInstance(archiveTimestamps.getObjectAt
                (archiveTimestamps.size() - 1));

        byte[] bytes = lastArchiveTimeStamp.getTimeStamp().getEncoded("DER");
        algId = lastArchiveTimeStamp.getAlgorithmIdentifier();
        MessageDigest md = MessageDigest.getInstance(algId.getAlgorithm().getId());

        byte[] newHash = md.digest(bytes);
        final PartialHashtree pht = buildPartialHashtree(newHash);

        final ASN1Sequence rhtSequence = new DERSequence(pht);
        reducedHashtreeForRenewal = new DERTaggedObject(false, 2, rhtSequence);

        return newHash;
    }

    /**
     * Renews a given {@link EvidenceRecord} instance, without renewing the hashtree.?
     *
     * @param evidenceRecord the {@link EvidenceRecord} to renew.
     * @param contentInfo the Timestamp token for renewal, provided as a {@link ContentInfo}.
     * @return the renewed {@link EvidenceRecord}.
     */
    public EvidenceRecord renewTimeStamp(
        EvidenceRecord evidenceRecord,
        final ContentInfo contentInfo)
    {
        final ArchiveTimeStamp ats = ArchiveTimeStamp.getInstance(contentInfo);
        evidenceRecord.addArchiveTimeStamp(ats, false);
        return evidenceRecord;
    }

    /**
     * Prepares a given {@link EvidenceRecord} for hashtree renewal.
     *
     * @param evidenceRecord the {@link EvidenceRecord} to renew.
     * @param data the original data to consider for the renewal.
     * @param algorithmIdentifier the digest algorithm to use for the renewal.
     * @throws IOException in the case the archive timestamp sequence of the evidence record
     * cannot be retrieved in DER encoding.
     * @return the root hash to timestamp in the hashtree renewal process.
     */
    public byte[] prepareHashtreeRenewal(
        final EvidenceRecord evidenceRecord,
        final Object data,
        final AlgorithmIdentifier algorithmIdentifier) throws IOException, NoSuchAlgorithmException {

        byte[] atsc = evidenceRecord.getArchiveTimeStampSequence().getEncoded("DER");
        MessageDigest messageDigest = MessageDigest.getInstance(algorithmIdentifier.getAlgorithm
            ().getId());
        byte[] ha = messageDigest.digest(atsc);

        if (data instanceof byte[])
        {
            final DataGroup dataGroup = new DataGroup((byte[]) data);
            return prepareHashtreeRenewal(ha, dataGroup, messageDigest);
        }
        else if (data instanceof DataGroup)
        {
            return prepareHashtreeRenewal(ha, (DataGroup) data, messageDigest);
        }
        else
        {
            throw new IllegalArgumentException("unknown object in prepareHashtreeRenewal: " +
                data.getClass().getName());
        }
    }

    /**
     * Prepares the hashtree renewal, for a provided {@link DataGroup}.
     *
     * @param ha the hash computed over the related {@link EvidenceRecord}'s archive timestamp
     * sequence.
     * @param dataGroup the data group to consider when renewing the {@link EvidenceRecord}.
     * @return the hash computed over the datagroup, concatenating its data objects' hashes with
     * the hash computed over the evidence records archive timestamp sequence.
     */
    private byte[] prepareHashtreeRenewal(final byte[] ha,
                                       final DataGroup dataGroup,
                                       final MessageDigest messageDigest)
    {
        TreeSet<byte[]> hashes = dataGroup.getHashes(messageDigest, ha);
        PartialHashtree partialHashtree = buildPartialHashtree(hashes);
        ASN1Sequence rhtSequence = new DERSequence(partialHashtree);
        reducedHashtreeForRenewal = new DERTaggedObject(false, 2, rhtSequence);
        return dataGroup.getHash(messageDigest);
    }

    /**
     * Actually performs the hashtree renewal, adding a new archive timestamp chain to the
     * provided {@link EvidenceRecord}'s archive timestamp sequence.
     *
     * @param record the {@link EvidenceRecord} to renew.
     * @param algId the identifier for the digest algorithm to use in the hashtree renewal process.
     * @param timestamp the timestamp to include.
     * @return the renewed {@link EvidenceRecord}.
     */
    public EvidenceRecord renewHashTree(
        final EvidenceRecord record,
        final AlgorithmIdentifier algId,
        final ContentInfo timestamp)
    {
        final ArchiveTimeStampSequence seq = getArchiveTimestampSequenceFromEvidenceRecord(record);
        final ArchiveTimeStamp ats = new ArchiveTimeStamp(algId, reducedHashtreeForRenewal, timestamp);
        ArchiveTimeStampChain chain = ArchiveTimeStampChain.getInstance(ats);
        if (seq != null) {
            seq.add(chain);
            record.addDigestAlgorithmIdentifier(algId);
            return record;
        }
        else
        {
            throw new IllegalArgumentException("invalid record");
        }
    }
}