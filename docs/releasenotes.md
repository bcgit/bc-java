# Bouncy Castle Crypto Package - Release Notes

## 1.0 Introduction

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms. The package is organised so that it contains a light-weight API suitable for use in any environment (including the J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

## 2.0 Release History

<a id="r1rv87"></a>

### 2.1.1 Version

Release: 1.87\
Date: 2026, TBD

### 2.1.2 Defects Fixed

- A KeyAgreement asked for its shared secret before doPhase returned data rather than refusing. javax.crypto.KeyAgreement specifies IllegalStateException for that state, but nothing in the provider tracked it, so each SPI handed back whatever its result field held: for Diffie-Hellman that was the private value itself - engineInit seeded result with x, so generateSecret() returned the private exponent padded to the prime's length and generateSecret("AES") an all-zero key taken from that padding - while ECDH returned null and its named-algorithm overload raised NullPointerException. BaseAgreementSpi now records whether a doPhase has completed the agreement since the last init and refuses the request with an IllegalStateException naming the algorithm, so every family in the provider - DH, ECDH and ECMQV, the SM2 exchange, both ECGOST families, XDH, SM9 and NewHope - answers the same way, and the DH SPI no longer holds the private value in that field at all.
- Mac.getInstance and KeyGenerator.getInstance by the HMAC SHA-512/224 and SHA-512/256 object identifiers (1.2.840.113549.2.12 and .13) failed, although the same algorithms resolved by name and the matching SecretKeyFactory aliases were registered: the SHA512 mappings called addHMACAlgorithm for the two truncated variants without the addHMACAlias that registers their OIDs against Mac and KeyGenerator. Both are now aliased, as every other HMAC in that class already was.
- A KTSParameterSpec naming an HKDF key-derivation function with a parameters field - a form the provider does not service - was accepted at Cipher init and then failed out of wrap or unwrap with an unchecked IllegalStateException neither method declares. The KTS key-wrapping Ciphers (ML-KEM, Classic McEliece, FrodoKEM, the composite KEM and RSA-KEM) now validate the spec's KDF when they take it, reporting an unserviceable one as the InvalidAlgorithmParameterException engineInit declares, which is what the javax.crypto.KEM services already did through KdfUtil.resolveKemSpec.
- A DTLS handshake deadlocked when a handshake message ahead of the peer's ChangeCipherSpec (a client's CertificateVerify, say) was lost while the ChangeCipherSpec and Finished behind it arrived: the record layer moved its read epoch on at the ChangeCipherSpec and then discarded every retransmission of the lost message as belonging to the old epoch, whose records are only accepted once the handshake has completed. Each side then waited on the other until a handshake timeout, if one was configured, ended it. Every client-authenticated handshake, and every handshake in which the server issues a NewSessionTicket, was exposed. Until the handshake completes, handshake records from the current epoch are now still accepted after the read epoch has moved on, and each message is checked against the epoch of the record that carried it. The DTLS loopback tests now run their handshakes at 10% datagram loss in each direction, with a client-authenticated handshake at 25%.
- The lightweight SubjectPublicKeyInfoFactory and PrivateKeyInfoFactory encoded a GOST R 34.10-2012 key on one of the legacy CryptoPro curves under id-GostR3410-2001, although RFC 9215 sec. 4.2 permits those curves for 2012 keys. The digestParamSet now decides: a GOST R 34.11-94 parameter set means 2001 (RFC 4491 sec. 2.3.2), a GOST R 34.11-2012 digest or none means 2012 with 256/512 taken from the curve field size, and any other value is rejected. GOST3410PublicKeyAlgParameters treats digestParamSet as OPTIONAL on both read and write per RFC 9215, and PrivateKeyInfoFactory now passes attributes through for ECGOST3410 keys (bc-csharp github #707).

- The name-constraint host canonicalisation removed a single RFC 1034 root-label dot, the only empty label a name may legally carry, but nothing refused the ones that are not legal: a dNSName, rfc822Name host or uniformResourceIdentifier host such as "example.com.." kept a phantom empty label after the strip and so matched no constraint at all, escaping an excluded subtree naming the host it appears to carry. A tested name whose host carries an empty label - a second trailing dot, a doubled dot or a leading dot - is now refused outright wherever a constraint of that type is in force, rather than canonicalised into a name it is not: removing the extra dots would decide on the caller's behalf that "example.com.." names example.com, which is not how a consumer resolving or comparing the name reads it, and refusing fails closed in both directions where canonicalising would newly admit such a name under a permitted subtree. The single trailing dot is canonicalised as before, a bare "." remains the root label rather than an empty one, and the guard is scoped to the host, so the doubled dot a quoted local part may legally carry is unaffected. Constraints are untouched - one may still begin with a dot, which is how this implementation spells "subdomains only" (github PR #2436).
- SSLContext.createSSLEngine() from the BCJSSE provider in the 1.86 bctls jar failed with NoSuchMethodError on every JDK from 9 up, leaving engine-based users of the provider (Netty, Vert.x and the like) unable to open a connection. The jdk1.5 and jdk1.9 copies of the package-private SSLEngineUtil had declared create(ContextData) with different return types since 2019 - SSLEngine and ProvSSLEngine - and the root ProvSSLContextSpi, compiled against the first, is paired at runtime with the versions/9 copy on any modern JDK. Until 1.86 the java9 compile had hidden this by implicitly recompiling the whole base tree into META-INF/versions/9 (447 classes, ProvSSLContextSpi among them); the -implicit:none added in 1.86 to stop that duplication exposed the mismatch. The jdk1.9 copy now declares the same return type as the root one, a JDK 25 test creates engines against the built jar, and a new multiReleaseCheck Gradle task on every distributed jar reads the constant pool of each class in the jar and in the sibling BC jars it depends on and fails the build when a member reference does not resolve against the copy of its target that a JDK would pair it with, so the class of defect cannot ship again; the same check runs on arbitrary jars, a published release included, as multiReleaseCheckJar (github #2448).
- The BCFKS key store derived its scrypt keys with the block size r in place of the parallelization parameter p, while writing the p the caller configured out to the store: BcFKSKeyStoreSpi passed getBlockSize() to SCrypt.generate for both arguments and never read the encoded parallelization parameter at all, so every store whose ScryptConfig gave a p other than its r encoded parameters that do not derive its own keys. The store was self-consistent - BC read back what BC wrote - but a conformant RFC 7914 reader computed a different key and so failed the integrity check and the store decryption, and BC could not open such a store written by anyone else. Derivation now follows RFC 7914. A store written by 1.86 or earlier is still read: the integrity check is retried under the old convention, and where a signature check leaves no MAC to settle it the store decryption is retried instead, in both cases reporting the failure of the encoded parameters rather than of the fallback. The write side is governed by org.bouncycastle.bcfks.scrypt_p_eq_r, default true, which writes p equal to r whatever the ScryptConfig asked for: the two conventions then agree, so a store written here is both RFC 7914 correct and readable by 1.86 and earlier. Clearing the property honours the configured p, which those releases cannot read unless p already equals r; the default is intended to become false in a later release, once enough of the installed base is writing parameters that describe themselves. Loading with a BCFKSLoadStoreParameter carrying a ScryptConfig accepts an encoded p equal to either the configured p or the block size, so a store round trips under the configuration that wrote it whichever way the property was set; every other parameter is compared as before. The parallelization parameter is now bounded alongside the cost parameter before the derivation, as the PKCS#8 and PKCS#12 scrypt paths already bound it.
- Building an evidence record was cubic in the number of data objects: SortedHashList and SortedIndexedHashList held their hashes in a LinkedList and found each insertion point by walking it with get(index), so a single add() was quadratic in the position it inserted at and building a list of n hashes cubic, and both lists sit on the generation path - the reduced hash tree of ERSArchiveTimeStampGenerator, the Merkle tree of BinaryTreeRootCalculator.computeRootHash(), and the hash list of every ERSDataGroup. Each now collects its hashes and sorts them once, in toList(); the sort is stable and the old insertion placed a hash after the last one comparing equal to it, which is where a stable sort puts it, so the order of the leaves and every root hash are unchanged. getFirst() answers with a scan rather than a sort and toList() sorts a copy, so neither accessor disturbs what has been added. Generating a time-stamp request over 8,000 data objects goes from about 210 seconds to under a tenth of a second, and 100,000 objects, which the old code could not reach in any practical time, takes about 0.2 seconds (github #2456).
- An ERSDataGroup recomputed its hash on every request rather than taking it from the cache ERSCachingData exists to provide: the group overrode getHash(), which left the calculateHash() the cache calls unreachable - and wrong, as it copied the member hashes with a loop bounded by the size of the empty list it was copying into, so it would have digested nothing had anything reached it. The computation is back in calculateHash() and the override is gone, so a group's hash is computed once per digest algorithm and previous-chain hash, as every other ERSData's is. The value itself is unchanged.
- ERSArchiveTimeStampGenerator rebuilt its reduced hash tree from the data objects on every call, so the usual generateTimeStampRequest() followed by generateArchiveTimeStamp() or generateArchiveTimeStamps() built it twice. The leaves are now built once and dropped when data or a previous chain is added. A Set of the data groups it had been given, which nothing ever read, has gone with it.
- Grain-128AEAD returned corrupted plaintext from a decryption driven in chunks. The stream cipher data operator splits a processBytes() call that spans the buffered authentication tag into two output segments, the bytes released from the tag buffer and then the bytes taken straight from the caller's input, and wrote the second segment at the caller's output offset instead of after the first, so the second segment overwrote the head of the first and the tail of the reported output was never written at all. The call still returned the full byte count, and because the engine's state update depends on the input and the keystream rather than on where the output lands, the tag still verified: the wrong plaintext came back with no error raised. Any chunk after the first that carried more than the 8 byte tag length was affected. Grain-128AEAD is the only engine that uses this operator, and one shot decryption, the encryption path and every other AEAD engine were unaffected. The second segment is now written at the advanced offset, matching the equivalent step of the general decryption path (github PR #2447).
- The AEAD stream cipher data operator, which Grain-128AEAD alone uses, wrote its output without first checking that the caller's buffer was long enough, so a short output buffer surfaced as an ArrayIndexOutOfBoundsException from inside the engine rather than as the OutputLengthException the general path reports for every other AEAD engine. Both directions of processBytes(), and processByte(), now check before anything is written or buffered, and only when the call releases output, as the general path does.
- The RFC 9709 content-encryption AlgorithmIdentifier, which carries the real algorithm inside the parameters of an outer id-alg-cek-hkdf-sha256, was unwrapped at only one of the points where a CMS recipient makes a decision about it. Key-size validation was corrected for plain key transport in 1.86, but the same call in the KEK, RSA-KTS and KEM recipients, and in the key-transport recipient's own ORI-KEM branch, still compared the recovered key against the outer identifier, which registers no key size, so setKeySizeValidation(true) silently checked nothing there; the setAllowedContentAlgorithms allow-list and the setMinimumTagSize floor were applied to the outer identifier on every recipient family, including the one already corrected, so neither constrained an RFC 9709 message. The unwrap now happens once for the key-size check and once for the two policy checks, and every recipient polices and validates the content-encryption algorithm the message actually carries. A recipient with no allow-list, no tag floor and no key-size validation configured behaves exactly as before; a caller who listed id-alg-cek-hkdf-sha256 in an allow-list in order to admit RFC 9709 messages must now list the content-encryption algorithms themselves (github PR #2446).
- A CMS message whose EncryptedContentInfo named the RFC 9709 key derivation but carried no readable content-encryption AlgorithmIdentifier in its parameters was reported as a NullPointerException, or as an IllegalArgumentException from the ASN.1 decoder, out of methods declared to throw CMSException, RecipientInformation.getContent() among them. The four places that resolve the wrapper - the CEK derivation, the content cipher selection, the key-size check, and the recipient's allowed-algorithm and tag-size checks - now share one resolver, which reports an absent or unreadable inner algorithm as a CMSException.
- The two YubiKey OpenPGP smart-card decryptor factories zeroized the user PIN array the KeyPassphraseProvider handed them rather than a copy of it, in a finally block after each private-key operation. Both providers BC ships return the application's own array by reference - DefaultKeyPassphraseProvider hands back the char[] it has cached for the key, and the provider inside OpenPGPApi.editKey returns its argument - so the first card operation destroyed the caller's PIN and the next private-key operation presented an all-zero PIN to the card, which the card refuses at the cost of a PIN retry. The PIN is now fetched as a clone the card operation owns - in OpenPGPSmartCard.requireUserPin, where the smart-card restructuring of this release put the fetch the two factories used to make - and KeyPassphraseProvider.getKeyPassword records that the array it returns stays owned by the provider (github PR #2444).
- The CRMF PKIPublicationInfo structure accepted, and could be built with, publication information RFC 4211 sec. 6.3 forbids: pubInfos MUST NOT be present if the action is dontPublish, and the field is SEQUENCE SIZE (1..MAX), so a present one is never empty. Both contradictions are now rejected with an IllegalArgumentException, on parsing and on construction from an array of SinglePubInfo. An absent pubInfos with the pleasePublish action, which is how the RFC spells "don't care", is unaffected, and no constructor in the library could produce either rejected form.
- The CMS RFC 8418 key agreement schemes (dhSinglePass-stdDH-hkdf-sha256/384/512, used with X25519 and X448) derived the key-encryption key with the user keying material in the entityUInfo of the ECC-CMS-SharedInfo but never as the HKDF salt, where RFC 8418 sec. 2.2 requires both - its recipe is salt = ukm, PRK = HKDF-Extract(salt, K), KEK = HKDF-Expand(PRK, DER(ECC-CMS-SharedInfo), SizeInOctets(KEK)). A message carrying a ukm therefore did not interoperate with a conforming implementation in either direction. The ukm is now passed as the salt as well, on both the generating and the receiving side, for those three schemes. A message with a ukm written by 1.86, the only release with RFC 8418 support, is not readable by this release and vice versa; messages without a ukm, and the X9.63-KDF key agreement schemes, are unaffected. The round-trip test now covers both the ukm and no-ukm cases for all six curve and scheme combinations, and checks the key-encryption key against the RFC's own recipe rather than only against BC itself (github #2454).
- A JKS store shorter than the SHA-1 checksum it ends with threw an unchecked ArrayIndexOutOfBoundsException out of KeyStore.load, which declares IOException for a store it cannot read: JKSKeyStoreSpi.validateStream subtracted the digest size from the raw store length without checking it, so the digest update clamped its negative length to zero and the System.arraycopy that lifted the stored checksum out failed on a negative source index. The length is now checked against the checksum plus the 12-byte header before the checksum position is used, and a store too short to carry either is reported as an EOFException. The JKS store is reached through the compatibility probe in AdaptingKeyStoreSpi, so any key store type that probes for it was exposed, and the legacy jdk1.1 and jdk1.4 provider copies carry the same fix (github #2451).
- A custom Argon2BytesGenerator.BlockPool was left to zeroise the blocks it recycled itself, and had no way to know how many blocks to hold: the generator returned each block to the pool with the password-derived data still in it, so only the FixedBlockPool BC ships cleared them, and sizing any other pool meant replicating the internal memory alignment and the block count of the fill step. The generator now clears every block before it goes back, so a pool neither has to clear nor can observe that data, and Argon2BytesGenerator.getBlockCount(memory, lanes) gives the number of blocks a run takes - which the default pool now uses, so it no longer discards and reallocates the four blocks of the fill step on every call. FixedBlockPool drops the two clears it no longer needs, leaving one zeroisation per block per use rather than two, and a generateBytes() that fails part way through now returns and clears the blocks it took, along with its own working buffer, rather than leaving both to the garbage collector (github #2452).
- The PKCS#12 key stores wrote the MAC key-derivation parameters of a file they had loaded into every file they wrote afterwards, under whatever password the caller stored with. For PKCS12-PBMAC1 that carried the loaded file's PBKDF2 salt, iteration count, key length and PRF, because the parameters were minted only when the store held none and were then assigned back, so the branch ran once per store object rather than once per write - which also meant one store reused a single PBKDF2 salt across every write, including writes under different passwords, with no file loaded at all. The classic store inherited the MAC salt length and digest algorithm the same way, so a file declaring a zero-length MAC salt was re-stored with one, and a file it had loaded under RFC 9579 handed on that file's PBKDF2 salt too, both stores reading PBMAC1. The values were also latched before the MAC was verified and were not cleared by the load(null, null) a caller must issue to recover, so a file that failed the check left them behind for the caller's own file. The PBKDF2 salt and the MAC salt are now generated for every write, the MAC salt at no fewer than 8 octets, nothing is latched until the file has verified, and an AlgorithmIdentifier supplied through a PKCS12StoreParameter is still written as it was given. A loaded file's PRF, key length, digest algorithm and MacData iteration count are still kept, the last as before; the PBKDF2 count is kept where it is at least the count being written with and raised to it otherwise, since the file being re-stored is not the one that count was chosen for - RFC 9579's own test vectors ask for 2048. That count is now org.bouncycastle.pkcs12.pbkdf2_it_count, default 65,536, the write-side counterpart for a PBMAC1 MAC of what org.bouncycastle.pkcs12.store_it_count is for the PBE. Reading is unaffected: a file's MAC is verified with the parameters it carries, whatever they are (github #2450).
- Cipher.SM9 took its data-encapsulation mode for decryption from the ciphertext rather than from the mode the Cipher was configured with. The GM/T 0080-2020 SM9Cipher structure names the mode in an enType field, but GM/T 0044.4 defines the authenticator as C3 = MAC(K2, C2), over the encapsulated message alone, so enType is not covered by it: re-encoding a ciphertext with the other enType leaves C1, C3 and C2 untouched and steers the recipient into the other mode. GM/T 0044.4 takes K1 and K2 from a single KDF output of klen = mlen + K2_len bits in stream mode and K1_len + K2_len bits in SM4 mode, where K1_len = 128, so when C2 is 16 bytes long the two modes make the identical KDF call and derive the same K1 and K2: a one-block SM4 ciphertext relabelled as stream mode passes the MAC check and the recipient returns K1 xor C2 - from which both the SM4 key K1 and the padded plaintext block follow, wherever that output is observable. CipherSpi now decrypts in the configured mode and rejects a ciphertext whose enType disagrees with it, so the mode is symmetric between encryption and decryption. That check compares two values a relabelling attacker can make agree, and so does not by itself protect a recipient whose Cipher is configured for stream mode - the relabelled one-block ciphertext then matches the configuration - so SM9Engine additionally refuses a 16-byte C2, the one C2 length at which the two modes collide, in both modes and both directions: on decryption, and on encryption a 16-byte message in stream mode and a message of fewer than 16 bytes, which pads to one block, in SM4 mode. Refusing the length on decryption protects the recipient that does so, but the message a relabelled ciphertext gives away is the SM4-mode sender's, who cannot tell whether the recipient's implementation refuses it, which is why the SM4 mode no longer produces one; messages of every other length are unchanged in both modes. A stream-mode ciphertext must accordingly be decrypted through a stream-mode Cipher ("SM9/XOR/NoPadding") rather than the SM4-mode default that Cipher.getInstance("SM9") gives; a message of fewer than 16 bytes has to be sent in stream mode, and one of exactly 16 bytes - a 128-bit key, say - in SM4 mode; and a ciphertext made by an earlier version whose C2 is 16 bytes long is no longer decrypted, whichever mode wrote it - a one-block SM4-mode ciphertext, or a stream-mode one carrying a 16-byte message. The SM9 KEM is unaffected.
- Decrypting an OpenPGP message in two steps - recovering the session key from a SKESK packet and then decrypting the SEIPD v1 body through PGPEncryptedDataList.extractSessionKeyEncryptedData() - stopped detecting a wrong passphrase. 1.86 suppressed the legacy CFB "quick check" on the two repeated prefix bytes for every session-key decryption, to close the Mister-Zuccherato oracle on the path a PKESK session key reaches, but the same class also carries password-derived session keys, where reporting the check is what identifies a wrong passphrase and lets the next passphrase or SKESK packet be tried. A SKESK v4 packet deriving the session key from the S2K output directly (no encrypted session key) yields a well formed session key for any passphrase, so a wrong one no longer failed at all: it surfaced as a parse or integrity failure further down the stream. BouncyCastle's own high-level API decrypts this way, so OpenPGPMessageProcessor took the first wrong passphrase offered for a success and never tried the remaining ones. A new PGPEncryptedDataList.extractSessionKeyEncryptedData(boolean) states whether the session key came from a password: true restores the check and with it the PGPDataValidationException on a wrong passphrase, the existing no-argument method goes on suppressing it, and the high-level API passes true on its passphrase paths alone, so a session key recovered from a public key operation is still never quick checked (github #2459).
- Both copies of PKIXCertPathReviewer (org.bouncycastle.pkix.jcajce and the legacy org.bouncycastle.x509) took the first date-valid CRL issued by the certificate's issuer as an answer about that certificate, applying neither of the RFC 5280 sec. 6.3.3 rules that decide whether a CRL covers it: the (b)(2)(i) match between a name in the CRL's issuing distribution point and a name in the certificate's distribution point, and the (d) intersection of the revocation reasons the two assert. Only the (b)(2)(ii) to (iv) onlyContains booleans were applied. A CA-signed, in-date CRL with no entries, scoped to another distribution point or to a partition of the revocation reasons, was therefore reported as proof of non-revocation - isValidCertPath() true with an empty error list for a certificate its own CA had revoked for key compromise, where CertPathValidator("PKIX") rejects the same chain against the same trust anchor - and it suppressed the distribution point fetch that would otherwise have retrieved the authoritative CRL. Where the reviewer makes the trust decision rather than serving as diagnostics beside a real validation this is a revocation bypass, and SignedMailValidator (bcmail) reaches it with the CRLs carried inside the signed message. Both copies now apply the (b)(2)(i) name match and require a CRL to cover every revocation reason before it can settle the certificate's status, through the public PKIXCRLValidator helpers the validation engine already uses, and keep looking when a candidate does not qualify - falling back, as before, to the distribution point fetch and then to the existing "no valid CRL found" error. A CRL carrying no issuing distribution point, one naming the certificate's own distribution point, and one naming the certificate issuer (the distribution point the engine falls back to) are all still accepted.
- RFC3280CertPathUtilities.checkCRL threw java.lang.NullPointerException rather than a CertPathValidatorException when every candidate CRL for a distribution point was skipped instead of rejected, which is what happens when the reasons a CRL covers add nothing to those already checked - the RFC 5280 sec. 6.3.3 (d) case - since the exception it rethrows is only ever recorded in a catch block. Validation failed closed either way, but outside the declared contract of CertPathValidator.validate(); a run with nothing recorded now reports "No valid CRL found.". All four copies are corrected: pkix, prov, and the prov jdk1.3 and jdk1.4 overlays.
- TupleHash prefixed an element of 2^28 bytes or more with a length computed in int arithmetic: org.bouncycastle.crypto.digests.XofUtils built the encode_string prefix of NIST SP 800-185 sec. 2.3.3 as left_encode(len * 8) with len an int, so the bit length wrapped before it reached the long parameter it was passed to. A single 256 MiB update wrapped it negative, and left_encode sizes its output by shifting its argument right eight bits at a time, which never reaches zero from a negative value, so the call did not return; at 512 MiB the length wrapped to zero and the element carried the prefix of an empty one, letting two different tuples absorb the same byte string - the ambiguity the tuple encoding of sec. 5.3 exists to prevent. The multiply is now widened, as the other left_encode and right_encode call sites in CSHAKEDigest, KMAC, TupleHash and ParallelHash already were, and left_encode and right_encode refuse a negative length rather than spinning on one, so a negative output length handed to the three-argument doFinal of TupleHash, ParallelHash or KMAC reports IllegalArgumentException instead of not returning. An element below 2^28 bytes is unaffected, the two arithmetics agreeing exactly there.
- KeyAgreement.init() reported an initialisation it could not carry out as an unchecked exception for the unified and VKO agreements, where the JCA declares InvalidKeyException and InvalidAlgorithmParameterException. The ECCDHU and X25519U/X448U services took a plain UserKeyingMaterialSpec, or no spec at all, and carried it into the agreement, throwing ClassCastException from the cast that follows; the DHU and DH MQV services accepted the initialisation and then threw NullPointerException from doPhase, where the absent spec is read back; and the ECGOST3410 and ECGOST3410-2012 VKO services put a null where the UKM belongs, although RFC 7836 sec. 4.3 makes the UKM optional with the value 1. Each of them now reports a parameter error as ECMQV already did, and the VKO agreements apply the RFC 7836 default, so an agreement initialised without a UserKeyingMaterialSpec derives the key a UKM of 1 gives rather than failing. The user keying material itself was not being dropped anywhere: every key agreement service carrying a key derivation function was checked for it.
- The RFC 5990 RSA-KTS CMS recipients (JceKTSKeyTransEnvelopedRecipient and JceKTSKeyTransAuthenticatedRecipient, through JceKTSKeyUnwrapper) took the keyLength carried in the message's RsaKemParameters as the number of octets for the key encapsulation mechanism to derive, and only compared it with the key-wrapping algorithm once the derivation had been done. EnvelopedData is not integrity protected and the recipient reaches this before anything about the message has been verified, so the declared length decided how much the key derivation function was asked to produce, and a large enough one also overflowed the bit count it was converted into. RFC 5990 sec. 4 fixes the length of the derived key as the key length of the data encapsulation mechanism's key-wrapping algorithm, so the recipient now derives that length and rejects a keyLength which disagrees with it before deriving anything, reporting it as the CMSException the API declares - the check the RFC 9629 KEMRecipientInfo path already made against its kekLength.

### 2.1.3 Additional Features and Functionality

- The CRMF certificate request message controls now include the RFC 4211 sec. 6.6 protocolEncrKey control, which names the key a CA is to encrypt its response with: org.bouncycastle.cert.crmf.ProtocolEncrKeyControl carries the SubjectPublicKeyInfo the control is defined to take, and CertificateRequestMessage.getControl() recognises id-regCtrl-protocolEncrKey alongside the regToken, authenticator and pkiArchiveOptions controls it already returned (github PR #2443).
- The CRMF certificate request message controls now cover all six RFC 4211 sec. 6 registration controls: org.bouncycastle.cert.crmf.PKIPublicationInfoControl (sec. 6.3), which says whether and where the CA should publish the certificate it issues, and OldCertIDControl (sec. 6.5), which names the certificate a request is asking to have replaced, join the regToken, authenticator, pkiArchiveOptions and protocolEncrKey controls, and CertificateRequestMessage.getControl() recognises both. CertificateRequestMessage.getControlValue() returns the raw value of any control present, including one the library has no Control implementation for - getControl() answers those with the same null it uses for a control that is absent - and org.bouncycastle.cert.crmf.jcajce.JcaProtocolEncrKeyControl and JcaOldCertIDControl build the two key- and certificate-bearing controls from a java.security.PublicKey and from the X509Certificate being replaced.

- The OpenPGP smart card API (bcpgsc) can now create signatures on a card as well as decrypt with one. The raw sign and decrypt operations moved onto OpenPGPSmartCard, so a backend can be emulated in software and the simulator exercises the same paths a card does; AbstractOpenPGPDocumentSignatureGenerator detects an external key and routes it to the card, with the content signer supplied through a pluggable PGPContentSignerBuilderProviderFactory; the YubiKey-specific decryptor factories are replaced by generic smart-card ones, ExternalOpenPGPKeyUtils converts an OpenPGPKey or OpenPGPCertificate into an external key, and the YubiKit dependency moves to 3.2.0. YubiKit remains compileOnly, so bcpgsc still ships with no third-party dependencies (github PR #2430).

- The promoted LMS private key (org.bouncycastle.crypto.params.LMSPrivateKeyParameters) keeps its Merkle tree in two bounded tiers in place of the WeakHashMap that held every node it ever computed: the top 63 nodes - the same ones its encoding persists - in a fixed array for the life of the key, and the authentication path of the last one-time key signed with, together with that leaf's ancestors, advanced under the key's lock as each index is claimed. The old map keyed every node below the top on objects nothing retained, so a leaf was collectable the moment it was inserted and the map's hit rate below the top depended on when the collector next ran, while its table still grew to 2^(h+1) entries during a tree build. A run of consecutive signatures now costs about (h - 5) / 2 + 1 leaf derivations each rather than either a cache hit or a 2^(h - 5) rebuild, with the rebuild remaining as the worst case at a half-tree crossing; shards and repositioned keys inherit the parent's retained path, and the encoding is unchanged. The tree built for the public key is built in path form, so a freshly generated key already holds the path of its first signature rather than rebuilding it - that signature went from 2.6 s to about 1 ms at h=15. The deprecated org.bouncycastle.pqc.crypto.lms copy is untouched.

- The JCE bindings for LMS/HSS have followed the lightweight ones into the main provider: org.bouncycastle.jcajce.provider.asymmetric.lms holds the KeyFactory, KeyPairGenerator and Signature implementations, and the key interfaces are promoted to org.bouncycastle.jcajce.interfaces.LMSKey and LMSPrivateKey. Both the BouncyCastle and the BouncyCastlePQC provider register the new classes for the "LMS" services and their id-alg-hss-lms-hashsig aliases, and the key-info converter the BC provider consults when it recovers a key from a SubjectPublicKeyInfo or PrivateKeyInfo - the path a certificate or a PKCS#8 key takes - returns them as well, so a key recovered that way verifies through either provider. The key generation parameter specs are promoted with them, as org.bouncycastle.jcajce.spec.LMSKeyGenParameterSpec and org.bouncycastle.jcajce.spec.LMSHSSKeyGenParameterSpec; the org.bouncycastle.pqc.jcajce.spec copies are deprecated and now extend them, so an existing spec object is one of the promoted type and keeps its own fromNames() and its org.bouncycastle.pqc.crypto.lms constructors and getters. The org.bouncycastle.pqc.jcajce.provider.lms classes and the LMS interfaces in org.bouncycastle.pqc.jcajce.interfaces remain and are deprecated; the old interfaces now extend the promoted ones, so code written against them still compiles and keys of the new classes still satisfy them.

- XMSS and XMSS^MT have been promoted the same way: org.bouncycastle.jcajce.provider.asymmetric.xmss holds the KeyFactory, KeyPairGenerator and Signature implementations for both, the key interfaces are promoted to org.bouncycastle.jcajce.interfaces.XMSSKey, XMSSPrivateKey, XMSSMTKey and XMSSMTPrivateKey, and the parameter specs to org.bouncycastle.jcajce.spec.XMSSParameterSpec and XMSSMTParameterSpec. Both providers register the promoted classes for the "XMSS" and "XMSSMT" services, their prehash variants and the six ISARA, IANA and PQC object identifier aliases, and the key info converters the BC provider consults for those six identifiers return them as well. The org.bouncycastle.pqc.jcajce.provider.xmss classes, the LMS-style interfaces in org.bouncycastle.pqc.jcajce.interfaces and the parameter specs in org.bouncycastle.pqc.jcajce.spec remain, deprecated: the interfaces extend the promoted ones and the specs extend the promoted classes, keeping their own parameter set constants, so existing code compiles and existing spec objects still drive the key pair generators. As with LMS, a verification key that is not one of the provider's own - a key of the deprecated class, or one from another provider - is now taken through its encoding rather than refused.

### 2.1.4 Additional Notes

- The sources and javadoc jars of the Ant-built distributions (jdk14, jdk15to18 and jdk13) no longer carry test material. Each module's javadoc target copies the package documentation it needs - org/bouncycastle/<area>/**/*.html - back into the module source directory that has already been compiled from, and zip-src zips that directory afterwards, so every test package's package.html arrived in the sources jar by that route; javadoc-util additionally copied org/bouncycastle/asn1/isismtt/**/*.java, which put test classes into the bcutil javadoc as generated pages, and javadoc-pg deliberately copied the gpg and bcpg test sources in order to document them. Separately the source copies excluded test material only one directory deep and only for *.java, because Ant reads ** as an any-depth wildcard just where it is a whole path segment, so anything nested further or with another extension - the PEM certificate fixtures under org/bouncycastle/est/test/san corrected in 1.86, and an ICAO master list under org/bouncycastle/asn1/icao/test - went through. The source and javadoc copies of every module now exclude test directories at any depth, and javadoc-pg no longer documents the test packages. org.bouncycastle.util.test is unaffected and still ships in the bcprov binary, sources and javadoc jars, as it does from the Gradle build: it is the SimpleTest framework the light-weight API's own test classes are written against, not test material of the distribution. No binary changes - the classes and resources of every Ant-built jar are identical to those of the 1.86 release - and the Gradle-built jdk18on artifacts never carried any of this.

<a id="r1rv86"></a>

### 2.2.1 Version

Release: 1.86\
Date: 2026, 11th September.

### 2.2.2 Defects Fixed

- The high-level OpenPGP API let a subkey inherit the primary key's Key Flags when its own Subkey Binding signature carried none, so a subkey bound with no flags counted as signing-capable for one check while the cross-certification check RFC 9580 sec. 5.2.1.8 requires of a signing subkey saw none and was skipped - letting a third party's public signing subkey be bound to an attacker's primary key and that party's genuine signatures verify under the attacker's identity. Flags are no longer inherited (CVE-2026-71887).
- The high-level OpenPGP API used a version 6 key carrying no valid Direct Key signature, falling back to the primary user ID binding as it correctly does for version 4. RFC 9580 sec. 5.2.3.10 requires the opposite, and since a v6 certificate carries its expiration and preferences there, stripping that one packet silently dropped them - the certificate went on offering subkeys of a key set to expire. isBoundBy now requires a valid Direct Key self-signature before any v6 component is treated as bound; version 4 is unaffected.
- The high-level OpenPGP API ignored the OpenPGPPolicy a caller had configured when verifying signatures on an inline message: OpenPGPMessageInputStream took the policy from the implementation's own default rather than from the processor doing the verification, so a hardened policy had no bearing on acceptance and getSignatures() reported isTestedCorrect() true for a signature that policy rejects. Both the one-pass and prefixed-signature paths now read the configured policy.
- The high-level OpenPGP API went on offering the subkeys of a certificate whose primary key had expired, the binding check evaluating only a subkey's own Subkey Binding signature - so the certificate contradicted itself, reporting the primary unbound while still handing out its subkeys. The primary key's expiration now applies to the whole certificate, as GnuPG and Sequoia treat it, and a subkey no longer inherits the primary's validity period, which RFC 9580 sec. 5.2.3.13 counts from the creation time of the key the carrying signature is made on.
- OpenPGPDocumentSignature.isValidAt(Date) reported a data signature as valid past the signature's own Signature Expiration Time (RFC 9580 sec. 5.2.3.18): it checked that the signature was correct and the issuing key bound and signing-capable at that date, but never the signature's own expiration, so it disagreed with isEffectiveAt() on the same object and with its own javadoc. isValid() and isValid(policy), which evaluate at creation time, are unchanged.
- The lightweight LMSSigner and HSSSigner refused a key wrapped in ParametersWithRandom, which is how BcContentSignerBuilder passes one once setSecureRandom() has been called, so BcHssLmsContentSignerBuilder failed with "Incorrect Key Parameters" and the two signers raised ClassCastException. All three now unwrap it, as the ML-DSA and SLH-DSA signers already did; the random is accepted and ignored, LMS deriving its message randomiser deterministically from the seed and one-time index.
- LMS signature verification did not apply two checks RFC 8554 sec. 5.4.2 requires before a signature is processed: step 2g, refusing a signature whose LMS typecode is not the public key's - without it a signature claiming a height-25 parameter set drove a 25-level computation against a height-5 key - and step 2i, refusing a leaf number outside the tree. Neither was a forgery, but both are attacker-chosen work the specification says to refuse up front. Both are now checked.
- The LMS and HSS key parameter classes now apply at construction the checks their decoders apply, so a key built directly cannot be one the decoder would refuse: LMSPrivateKeyParameters accepted an identifier of any length where the decoder reads exactly 16 bytes, and left q, maxQ and the seed length unchecked, while HSSPrivateKeyParameters checked neither its level count nor that it had a component key and chaining signature per level. The decoders now report a bad version or seed length as IOException rather than IllegalStateException.
- In the LMS JCE layer, LMSKeyGenParameterSpec.fromNames knew all twenty LMS parameter-set names but only four of the sixteen LM-OTS ones, so none of the SP 800-208 n24 or SHAKE sets could be named; all sixteen are now present. initialize(int, SecureRandom) now reports InvalidParameterException as the JCA specifies, and BCLMSPrivateKey.getIndex takes the exhaustion check and the index read under one monitor.
- KeyPairGenerator.initialize(int, SecureRandom) is documented to raise InvalidParameterException when the key size is not one the generator supports, and thirty of them raised a bare IllegalArgumentException instead. Every generator in BCPQC, and the ML-DSA, ML-KEM, SLH-DSA, Classic McEliece, FrodoKEM, NTRU and composite ones in the BC provider, now raise the documented type - which extends IllegalArgumentException, so existing catches still match. The two RSA generators translate the lightweight refusal through a new SecurityExceptions.invalidParameterException factory.
- KeyPairGenerator.initialize(AlgorithmParameterSpec, SecureRandom) had the same shape of problem, only 44 of the 304 services the two providers register reporting an unusable spec as the InvalidAlgorithmParameterException that method declares. The twenty-three PQC generators that resolve a parameter set by name case-folded it without checking, so a spec with no getName(), or a null spec, produced a NullPointerException. All 304 now report the declared exception - a checked one, so a caller catching what they threw before has to catch the declared type instead.
- An HSS private key claimed the two records of its position under two different monitors: generateLMSContext incremented the top-level index under the HSS key's own monitor and only then claimed the component key's one-time index q. A getEncoded() issued in between produced an encoding this implementation's own decoder rejects, and two threads meeting at a bottom-tree boundary could take consecutive top-level indices and claim the same q, leaving the key unable to be encoded, cloned or sharded. No one-time key was reused. Both records are now claimed under one monitor.
- TimeStampToken parsed the attacker-controlled TSTInfo of a time-stamp token inside a try catching only CMSException, so a malformed TSTInfo let an IllegalArgumentException or NoSuchElementException escape its declared TSPException, IOException contract; a token signed by no signers or by more than one raised a bare IllegalArgumentException. Both are now reported as TSPException, and asn1.tsp.TSTInfo now requires the five to ten elements RFC 3161 sec. 2.4.2 gives the type (github #2415).
- Neither the HSS nor the XMSS^MT private key decoder checked its declared index against the traversal state stored beside it, though the two are independent records of the same position. A stored key whose index had been rolled back while its state stayed advanced - a partial write, a restore from backup - was accepted, and then signed a second message under a one-time key it had already used, producing a signature that verified. Both decoders now require the two to agree, as the single-tree XMSS decoder already did, and the encoded BDS state carries a checksum over itself with the owning key's public seed hashed in front - an error-detecting code, not integrity protection (github #2414).
- In the XMSS and XMSS^MT JCE layer, KeyPairGenerator.initialize(int, SecureRandom) reports InvalidParameterException, which is what the JCA specifies and which extends the IllegalArgumentException it raised before, so existing catches still match. This is the XMSS counterpart of the same correction made to LMSKeyPairGeneratorSpi.
- BCXMSSPrivateKey.getIndex and BCXMSSMTPrivateKey.getIndex took the exhaustion check and the index read as two separate calls, so a signature taken by another thread between them spent the last usage and the read returned maxIndex + 1 - the one index past the end of the key, handed back as though it were the next one-time key to be used. Both reads are now taken under the key parameters' own monitor, as BCLMSPrivateKey.getIndex was. No one-time key is reused by this.
- The S/MIME example smoke test in the misc module drove SendSignedAndEncryptedMail against smtp.gmail.com, finishing with Transport.send() under JavaMail's defaults, which have no connect timeout: where outbound port 25 is silently dropped, as on many home networks, ./gradlew build hung in :misc:test indefinitely with "0 tests completed". The test now delivers to an SMTP stub on a loopback port, with timeouts as a backstop, and asserts the message arrived (github #2407).
- Composite ML-KEM encapsulation took the traditional component public key bytes it feeds the KEM combiner from the recipient key's own encoding, while decapsulation recomputes the point and so always produced an uncompressed one. Section 4 of draft-ietf-lamps-pq-composite-kem requires an uncompressed EC point, so a component key that encodes itself compressed left the two sides deriving different shared secrets with no error reported on either. The EC component is now normalised wherever the engine serialises one, as is CompositePublicKey.getEncoded(); decoding still accepts either form.
- Composite ML-KEM encapsulation threw a NullPointerException, wrapped in an IllegalStateException out of KeyGenerator.generateKey(), when the SecureRandom it was given was null - which javax.crypto.KEM.newEncapsulator() documents as a request for the provider's default. The three RSA-OAEP composites were the ones affected, drawing the traditional shared secret from that random directly. CompositeMLKEMEngine now defaults one through CryptoServicesRegistrar, and clears the ML-KEM component's shared secret as sec. 3.5 of the draft requires.
- CompositePublicKey.getAlgorithm() and CompositePrivateKey.getAlgorithm() returned null for all twelve Composite ML-KEM parameter sets, both classes resolving the name through the composite signature index only - so the standard idiom of KeyFactory.getInstance(key.getAlgorithm()) raised a NullPointerException. The lookup now falls back to the composite KEM index, and the SubjectPublicKeyInfo / PrivateKeyInfo constructors dispatch to the composite KEM key factory for those OIDs (github #2404).
- The org.bouncycastle.jcajce.spec.KEMKDFSpec constructor stored a null otherInfo as given, so the KMAC-128, KMAC-256 and SHAKE-256 branches of KdfUtil.makeKeyBytes read its length without a guard and threw NullPointerException, where the KDF2, KDF3 and HKDF branches tolerate a null. No provider path reached it, every Builder in the package already mapping null to empty, but the constructor is protected on a public class. It now stores empty, so a null and an explicitly empty otherInfo derive the same key.
- QR-UOV signature verification accepted a signature encoding that was not canonical, even after the trailing-byte fix of github #2403. Each F_q element is stored in ceil(log2 q) bits, one more pattern than the field has elements, so an element written as q verified as the same element written as zero would, and the bits padding the last element to the byte boundary were never read - a single qruov_5_q7_L10 signature measured 256 spare bits, so on the order of 2^256 byte strings verified for one message and key. Verification now rejects any element outside [0, q) and any set padding bit (github #2403).
- SNOVA signature verification ignored four bits inside the signature for any parameter set whose solution is an odd number of GF(16) nibbles - sixteen of the forty-four. The last byte of the encoded solution carries a single nibble and the signer leaves the top four bits zero, but the decoder did not read them, so sixteen distinct byte strings verified for one signature. The verifier now requires those bits to be zero (github #2403).
- SnovaPrivateKeyParameters did not validate the length of the private key encoding handed to it, and SnovaParameters.getPrivateKeyLength() reported the expanded length even for a parameter set whose private key is the seed pair. Since that encoding reaches the constructor straight from a PKCS#8 blob, a seed-form key with extra bytes appended was accepted and signed under a different derived key. The length is now checked at construction, and the signing retry loop gives up after its 256 attempts rather than spinning forever on a singular system (github #2403).
- MayoSigner and MayoKeyPairGenerator did not clear several buffers holding secret key material that the MAYO reference implementation explicitly clears - the oil space O, the expanded L, the central map intermediates, the expanded seed and the packed echelon form of the secret linear system. Separately, signing emitted a signature built from a failed attempt's state where the reference reports failure, and AIMerSigner.generateSignature returned an empty array on failure; both now throw.
- Five PQC signature schemes - MAYO, SNOVA, QR-UOV, SQIsign and AIMer - returned the NIST crypto_sign "sm" signed-message envelope from generateSignature() rather than the signature. Verification then checked only that the buffer was long enough, so trailing bytes could be appended to a valid signature and a signature encoding was not unique; and the envelope propagated into every X.509 certificate, CRL, CMS SignedData and TLS CertificateVerify built on the operator layer, each carrying a verbatim copy of the signed data inside its own signature field. generateSignature() now returns the bare signature and verification requires exactly the parameter set's signature length. **This is a behavioural change for signatures produced by an earlier release**, which can be recovered by taking the leading signature-length bytes - the trailing ones for AIMer (github #2403).
- The MLS implementation did not bind an X.509 credential to the LeafNode's signature_key: LeafNode.verify() checked the leaf's signature against the signature_key declared in the leaf, while the credential's certificate chain was stored but never parsed, so a leaf could carry one party's certificate while being signed by an unrelated key and still be accepted under that party's identity (RFC 9420 sec. 5.3). The end-entity certificate's subject public key must now equal signature_key; chain and identity validation to a trust anchor remain the application's responsibility (CVE-2026-71885).
- The SecureRandom supplied to JceCMSContentEncryptorBuilder.setSecureRandom() did not drive the content IV / nonce for any algorithm other than RC2: every other content-encryption algorithm reached generateParameters() on an uninitialised generator, so the IV or nonce was drawn from a default SecureRandom and the setting silently ignored. The generator is now initialised with the supplied random. Note that the JournalingSecureRandom reproducible-encryption support now records the IV in the transcript, so a resumed session regenerates it from the replayed randomness.
- The NTRU LPRime, NTRU+ and SMAUG-T KEM generators threw a NullPointerException when constructed with a null SecureRandom, where every other KEM generator - including NTRU LPRime's own SNTRU Prime counterpart in the same package - defaults one through CryptoServicesRegistrar.getSecureRandom(). This is reachable from the lightweight API directly, and from javax.crypto.KEM, whose newEncapsulator() documents a null random as a request for the provider's default.
- FrodoKEMEngine kept a single SHAKE instance in a field, so an engine reached concurrently produced wrong results - and FrodoKEMExtractor holds one engine for its lifetime, so two threads extracting through one extractor interleaved the digest's absorb and squeeze phases, yielding shared secrets that silently did not match the sender's, or an IllegalStateException. The digest is now built per call, as CMCEEngine's already was. Single-threaded results are unchanged.
- The BCJSSE provider carried the TLS 1.2 coupling between the supported_groups extension and ECDSA over into TLS 1.3, treating an ECDSA signature scheme as usable only while the corresponding curve was among the named groups enabled for key exchange. RFC 8446 sec. 4.2.7 scopes supported_groups to key exchange only, signature algorithms being negotiated independently (sec. 4.2.3), so the restriction has been removed for TLS 1.3. Ed25519, Ed448, the RSA schemes and default named-group configurations were unaffected.
- The bcmail module descriptor did not declare its javax.mail / javax.activation dependences, so a module-path consumer hit IllegalAccessError or module-resolution failures when the S/MIME classes touched the mail API. The descriptor now requires them optionally (requires static) under all four module names those libraries are known by - mail and activation, and java.mail and java.activation - since a hard requires on any one would break users of the others (github #2389).
- Four type-coercion helpers in the OER / IEEE 1609.2 (ITS) decoder tested the wrong type in the identity fast path that lets a getInstance() factory return an argument already of the target type: UINT32.getInstance and the etsi102941 Version.getInstance guarded on UINT8, so neither accepted its own type; EtsiTs103097DataEncryptedUnicast.getInstance guarded on its sibling and then cast; and OEROptional.getObject(Class) transposed its isInstance arguments, leaving the cast path dead. Each guard now names the type it returns (github #2373).
- DefaultAlgorithmNameFinder and DefaultSignatureNameFinder had no entries for the ShangMi algorithms, so an SM2 signature AlgorithmIdentifier that DefaultSignatureAlgorithmIdentifierFinder itself produces came back named only by its OID string. Both finders now name sm2sign_with_sm3 as SM3WITHSM2 and sm2sign_with_sha256 as SHA256WITHSM2, and DefaultAlgorithmNameFinder also names the sm3 digest. The rest of the GM arc remains unnamed (github #2377).
- The RFC 4998 evidence-record classes compared the digest AlgorithmIdentifier named by a time-stamp authority with their own using AlgorithmIdentifier.equals(), which compares encodings - so a TSA naming SHA-256 with an explicit NULL parameters field, DigiCert among them, was rejected with "time stamp imprint for wrong algorithm" against BC's own calculator, which leaves them absent. RFC 5754 sec. 2 requires a receiver to accept either. The comparisons now use the new AlgorithmIdentifier.areEquivalent, which treats an absent parameters field and NULL as the same (github #2379).
- EDIPartyName.toASN1Primitive emitted the nameAssigner and partyName DirectoryStrings without their context tags, so an EDIPartyName built through its public constructor could not be parsed back by getInstance. RFC 5280 sec. 4.2.1.6 tags both members explicitly, DirectoryString being a CHOICE, which X.680 does not allow to be tagged implicitly - the decoder already had this right and the encoder now matches. Note a GeneralName carrying an untagged ediPartyName, including one BC itself produced, is now rejected (github #2380).
- RSASSA-PSS could not be used with a RIPEMD digest through the JCA: nothing registered the RIPEMD PSS signatures, and the generic route with an explicit PSSParameterSpec failed too, DigestFactory returning null for a RIPEMD name and isSameDigest - an allow-list of the SHA families and MD5 - reporting two identical RIPEMD names as different digests. isSameDigest now answers true for equal names whatever the digest, DigestFactory recognises the three RIPEMD sizes, and the PSS signatures and their DefaultSignatureAlgorithmIdentifierFinder entries are registered. BC still requires the PSS and MGF1 hashes to match (github #2381).
- The opt-in key-size validation on CMS key-transport recipients (JceKeyTransRecipient.setKeySizeValidation(true)) never ran for a message using RFC 9709 CEK derivation: the branch that should have selected the content-encryption algorithm from the KDF parameters compared the encrypted-key byte array against an object identifier - a comparison that is always false - so the check fell through to a lookup with no registered key size and silently checked nothing. The recipient now dispatches on the content-encryption algorithm OID. Matching key sizes, non-HKDF messages and recipients that do not enable validation are unaffected (CVE-2026-71892).
- The OpenPGP v6 SEIPD packet parser read the AEAD chunk-size octet without bounding it. The chunk length is 2^(chunkSize + 6) bytes and the decryptor allocates that up front, so a crafted v6 message - reachable with only the recipient's public key - declaring chunkSize 24 forced a 1 GiB allocation on decrypt, and 25 threw NegativeArraySizeException: a pre-authentication resource exhaustion. This is the version 6 sibling of the v5 packet issue fixed under CVE-2026-3505. The octet must now be within 0..16, checked at parse before any allocation.
- The Ed25519 KeyFactory in the JDK 11+ and JDK 15+ multi-release overlays had drifted from the base implementation on the OpenSSH key-spec path, using the no-passphrase parsePrivateKeyBlob overload - so a passphrase-encrypted openssh-key-v1 Ed25519 key that decoded on JDK 8 failed on JDK 11 and later, and parse errors escaped as raw runtime exceptions. The overlays now match the base implementation, and the OpenSSH paths across the RSA, DSA, EC and Ed25519 key factories consistently raise InvalidKeySpecException. The multi-release test tasks now exercise these key specs.
- The Ant-built utility jars (bcutil-jdk15to18, bcutil-jdk14) duplicated org.bouncycastle.asn1.iana.IANAObjectIdentifiers, which since 1.85 lives only in core and so already ships in bcprov, because the build-util target still copied the iana package into bcutil - failing an Android/R8 build with "Duplicate class" for a project depending on both. The package is no longer bundled into bcutil; the Gradle jdk18on jars were already correct (github #2356).
- org.bouncycastle.util.BigIntegers.intValueExact (and the byte/short/long variants) delegated to BigInteger.intValueExact from 1.85, a Java 8 method Android only provides from API level 33, so on earlier Android versions any code path using them - most visibly loading a PKCS12 keystore, whose iteration-count validation calls intValueExact - crashed with NoSuchMethodError. The range checks are open-coded again, as they were in 1.84 (github #2369).
- GOST R 34.10-94 signing raised the domain generator to the per-signature nonce k with a bare BigInteger.modPow, whose running time varies with the exponent - and recovering k from that timing yields the private key straight out of s = k\*m + x\*r. k is now randomised with a random multiple of q before it is raised, exactly as DSASigner already does. Since the domain parameter a has order q the signature is unchanged, though the known-answer vectors now consume one further byte from their FixedSecureRandom.
- KCCMBlockCipher (DSTU7624-128/256/512 CCM mode) returned the input length rather than 0 from getUpdateOutputSize(int), but like CCMBlockCipher/KGCMBlockCipher it buffers all input until doFinal and produces no output on an update. Through the JCA layer this made the caller-supplied-buffer Cipher.update(input, inOff, inLen, output, outOff) reject a correctly sized output buffer with "javax.crypto.ShortBufferException: output buffer too short for input." when decrypting. getUpdateOutputSize now returns 0, matching the sibling CCM/KGCM modes (github #2354).
- J-PAKE raised values to exponents carrying private material with bare BigInteger.modPow calls - the private ephemerals x1 and x2, the password-bearing x2\*s and its negation, and the v behind each Schnorr proof, which together with the published r would give up x. All are now randomised with a random multiple of q before being raised, which is sound because the generator and each received value are checked with g^q = 1. JPAKEUtil.calculateA and calculateKeyingMaterial gained SecureRandom overloads, and the three-argument calculateGx, which has no q to work with, is deprecated. The EC variant already routed its scalars through ECAlgorithms.multiplySecret.
- The PKIX CertPathBuilder matched candidate issuers by subject name only during its depth-first search, so a CertStore holding many self-issued certificates that share one subject name and never chain to a trust anchor could be explored as a large number of partial paths. The builder now bounds the nodes visited per build, configurable via the org.bouncycastle.x509.max_cert_path_build_nodes system property (default 262144), failing with a CertPathBuilderException naming the property when exceeded.
- A group of parse and revocation-handling entry points let an unchecked runtime exception escape on empty, content-less or out-of-range input instead of the checked exception each declares - the malformed input was rejected either way, but the leaked type could escape a documented throws contract. Each now fails with its declared type: the TSP, CMS, CMC, EST, CRMF, OpenSSL and PKCS entry points, ECCurve.decodePoint and OpenSSHPrivateKeyUtil.parsePrivateKeyBlob, and the PKIX revocation code, which no longer leaks on an out-of-range CRLReason, an absent reasons mask or an OCSP response with no nonce. Well-formed input is unaffected.
- java.security.AlgorithmParameters.init(byte[]) is contracted to throw IOException on a decoding error, but several BC AlgorithmParameters SPIs (RSA OAEP/PSS, EC, DSA, DH, ElGamal, IES, GOST, and the GCM/CCM parameters of AES, ARIA, LEA and SM4) could leak an unchecked exception. Each affected engineInit(byte[]) and both loadParameters helpers now convert a leaked runtime exception to IOException; well-formed parameters are unaffected.
- The Classic McEliece fixed-weight vector generator (ISO/IEC 18033-2 sec. 13.11 step 4) checked its candidate indices for repetition with a scan that stopped at the first collision, so the time taken to reject a candidate set depended on which pair of indices collided. Those indices are the support of the error vector the encapsulation is built from. The scan now visits every pair and accumulates the answer through a branchless equality mask, so a rejection costs the same wherever the collision was; ciphertexts, shared secrets and the known-answer vectors are identical. A hardening rather than a fix for a demonstrated attack.
- The (D)TLS API and BCJSSE could not generate an RSA-PSS handshake signature when the private-key operation was delegated to a provider registering only the generic "RSASSA-PSS" algorithm and taking the digest from a PSSParameterSpec - the shape of SunMSCAPI, so Windows smart-card client keys failed the handshake once the digest-specific name lookups had been exhausted. JcaTlsCrypto now falls back to the generic name, with the digest, MGF and salt length still supplied through the PSSParameterSpec.
- Two follow-ups to the 1.85 fix for issue #781 in ESTService.getCSRAttributes. The 204 / 404 branch drained the error body with Streams.drain, which reads until EOF, so a truncated chunked 404 on a kept-alive connection with no SO_TIMEOUT could wedge the calling thread; the drain is now bounded by the declared Content-Length and never seeks EOF. And a failure while closing the response no longer masks a 204 or 404, where RFC 7030 sec. 4.5 makes the status alone the answer; on a 200, where the body must parse, close() failures are still raised (issue #781).
- ECCSI signing inverted HE + r\*SSK modulo q with BigInteger.modInverse, which is variable time in the value it inverts - and that value carries the secret signing key, so the timing of every signature leaked information about it. It now uses the constant-time BigIntegers.modOddInverse, with the sum going through modAdd and both products through the new modMult. Two range requirements RFC 6507 states had to be enforced to make that well defined: the per-signature nonce j is now drawn in [1, q-1] rather than uniformly over q's bit length, and an SSK outside [1, q-1] is rejected at init. Signatures are unchanged for in-range draws. ECCSISignerTest was also never registered in the crypto RegressionTest, and is now.
- ECCSISigner drew the per-signature value j - and r, which is derived from it - only when the signer was initialised, so a signer asked to sign a second message reused both: two RFC 6507 signatures formed over one j share their r, and their s' values then determine the SSK by linear algebra, so anyone holding both signatures could recover the secret signing key. Both are now retired once a signature has been formed and redrawn for the next message. Initialising with bare ECCSIPrivateKeyParameters now draws from the default SecureRandom rather than throwing NullPointerException.
- ECCSISigner assigned r the value Jx mod q, where RFC 6507 sec. 5.2.1 assigns it the N-octet Jx itself and sec. 5.2.2 has the verifier check Jx = r modulo p - so for roughly one signature in four billion on the RFC's P-256 parameters BC transmitted r = Jx - q and a conforming external verifier rejected a signature BC had itself produced. r now carries Jx unreduced, so any signature whose Jx was already below q is byte for byte unchanged. N is now derived from the larger of the field and order bit lengths, so signatures on some cofactor curves grow and do not interoperate with those of earlier releases.
- JceKTSKeyTransRecipient was the only recipient implementation in org.bouncycastle.cms not derived from AbstractRecipient, so a caller hardening their CMS decrypt path with a content-encryption algorithm allow-list and a minimum AEAD tag size got that protection for every recipient type except RSA-KTS key transport, silently. It now extends AbstractRecipient and enforces both checks before unwrapping, exposing the same setAllowedContentAlgorithms / setMinimumTagSize configuration as the other recipient families; a recipient with neither constraint configured behaves exactly as before.
- The OpenPGP AEAD encryption stream in the lightweight operator path (BcAEADUtil) encrypted each chunk in place into a buffer sized for the plaintext alone, relying on two properties AEADBlockCipher does not promise: that output never overtakes aliased input, and that doFinal's output fits within the plaintext's length. The pure-Java GCM/EAX/OCB engines satisfy both, but a conforming implementation that buffers differently could overrun the buffer or silently produce a valid encryption of corrupted plaintext. Each chunk is now encrypted into a buffer sized from getOutputSize(); output with the engines in the tree is unchanged.
- SICBlockCipher (CTR/SIC mode) performed no counter-range checking when initialised with a full-block IV, so the counter could be advanced 2^64 or more blocks past its start - beyond which getPosition() and the skip arithmetic silently misrepresent the stream position - and a backward skip below the initial counter wrapped silently. The advance since init is now bounded, the short-IV check also fires on the processBlock() path which previously ran unchecked, and two long-overflow defects in the skip arithmetic are fixed. Counter adjustment is now a single carry-propagating addition rather than repeated increments, so a skip's cost no longer grows with its distance. Data produced within range is unchanged.
- Salsa20Engine.skip(Long.MIN_VALUE) - and, through the shared implementation, the same call on ChaChaEngine, ChaCha7539Engine, XSalsa20Engine and XChaCha20Engine - negated its argument into itself, making the skip a silent no-op that still returned as though it had moved 2^63 bytes backwards, leaving the caller's stream position misaligned with the keystream. The move is now split in two, so it either lands exactly (the 64-bit block counter makes positions beyond 2^63 legitimate) or fails with the existing "attempt to reduce counter past zero." exception.
- Diffie-Hellman key agreement raised the peer-supplied public value to the private exponent with a bare BigInteger.modPow, in both DHBasicAgreement and DHAgreement, so with a static private key and a peer able to choose its public value and repeat the agreement the timing leaked information about the exponent. The exponent is now blinded with a random multiple of p-1 before each exponentiation; any value coprime to a prime p raised to p-1 is 1 by Fermat, so shared secrets are unchanged. DHBasicAgreement now uses a supplied ParametersWithRandom as the blinding source rather than discarding it.
- The ReasonsMask helper used by PKIX CRL revocation processing (in both the prov jce/provider and pkix pkix/jcajce copies) answered hasNewReasons through an operator-precedence slip - (a | b ^ a) is (a | b) - so any CRL carrying a non-empty reasons mask appeared to contribute new revocation reasons; the call site in RFC3280CertPathUtilities also passed the processed and interim masks in swapped positions, which the broken symmetric test had hidden. hasNewReasons now tests whether the candidate mask carries reasons outside the existing one, the call site is oriented correctly, and processCRLD computes the RFC 5280 sec. 6.3.3 (d)(1)-(d)(4) reasons intersection directly, treating absent reasons as all reasons.
- The CRL revocation-entry evaluation (getCertStatus) existed in four drifted copies, two of them each missing a different hardening the others had: the copy behind the pkix PKIX revocation path did not reject CRL entries carrying unsupported critical extensions, which RFC 5280 sec. 6.3 requires, and the copy behind the legacy org.bouncycastle.x509 API let an unchecked exception from a malformed indirect-CRL certificateIssuer escape. Both are fixed, the two pkix-side copies are collapsed into one, and the sec. 6.3.3 (i)/(j) revocation-effectiveness rule is single-sourced in PKIXCRLValidator.
- Naccache-Stern decryption leaked on two counts. It raised the caller-supplied ciphertext to an exponent derived from phi(n) - which is the private key - with a bare BigInteger.modPow; that exponent is now randomised with a random multiple of phi(n), leaving recovered plaintexts unchanged by Euler. And each plaintext digit was recovered by searching a precomputed table with Vector.indexOf, which stops at the match - and the index of the match is the digit, so the number of comparisons revealed the plaintext to anything able to time a decryption. The table is now searched in full with the index selected by mask.
- The HKDF SecretKeyFactory implementations, and on JDK 25 the javax.crypto.KDF implementation behind the same names, each held a single HKDFBytesGenerator and ran every derivation through it. Both are expected to be usable from more than one thread, but that generator's digest carries mutable state, so concurrent derivations interleaved and produced wrong output or threw - measured at roughly 5,900 wrong or failed results out of 6,000 derivations across six threads. Each invocation now builds its own generator from a copy of the template digest; single-threaded output is unchanged.
- The FAEST signature's proof-of-work grind check and challenge decoding branched on secret-derived data: checkChallenge3 returned as soon as it found a set bit in the grind range, and decodeAllChall3 as soon as a decoded index exceeded its tree bound, so the timing of a rejected candidate revealed which bit or which index caused the rejection. Both now fold their result into an accumulator over the full range and test once at the end. A hardening - the accepted grind count is published in the signature anyway - and signature output is unchanged.
- NTRU reduced secret values with the % operator in three helpers, each a port of a reference routine that is deliberately division-free, so the reduction leaked its operand through the data-dependent cycle count of an integer division. Polynomial.modQ took q as a parameter, which the JIT cannot strength-reduce to a multiply the way it can a constant, so it emitted a genuine hardware division on every call on the decapsulation path, where the dividend derives from the private key; it is now x & (q - 1), exact because q is always a power of two. The three mod3 helpers now use the reference's division-free fold. All four produce identical results across their entire input domain, so keys, ciphertexts and the known-answer vectors are unchanged (CVE-2026-18036).
- HQC leaked secret-derived data through two side channels. GF implemented GF(2^8) multiplication, squaring and inversion with lookup tables indexed by field elements, so the cache line touched was a function of the operand - the same weakness as an AES T-table implementation - and the tables were reached with secret inputs on both sides of the KEM; GF is now table-free and branch-free. Separately, HQCEngine.generateRandomSupport left its duplicate scan at the first collision and stored each accepted position at a secret-derived address; because that sampler re-expands the support from the long-term secret key seed on every decapsulation, the draw sequence is identical each time, making the timing a fixed fingerprint of the private key measurable without chosen ciphertexts. It now examines every candidate with no early exit and writes by masking. Output and the known-answer vectors are unchanged (CVE-2026-18040).
- MLS stores RFC 9420's uint32 leaf_index in a signed int, so a wire value with the top bit set decodes negative - a legitimate encoding that must still decode. SecretTree.hasLeaf and Group.validateRemove compared it directly against the tree's small positive leaf count, and a signed comparison treats any negative int as below a positive bound, so an out-of-range sender passed the membership check: for hasLeaf that drove LeafIndex.directPath() into a cycle that never reaches the root, growing its result list until the heap was exhausted - a denial of service any group member could trigger against every other. Both comparisons now interpret the value as unsigned (CVE-2026-17507).
- The key-confirmation MAC-tag check in the J-PAKE, EC J-PAKE and Owl key-agreement utilities compared the expected and partner tags with BigInteger.equals(), which returns as soon as the signum, the magnitude length or any magnitude word differs, so the time taken to reject a wrong tag varied with how much of the expected tag matched. All three now compare with Arrays.constantTimeAreEqual over the encodings. This is defence in depth rather than a directly exploitable flaw: producing a candidate tag requires the shared MAC key, and a failed key confirmation ends the session.
- Shamir secret splitting (org.bouncycastle.crypto.threshold) leaked the material it exists to protect through timing and cache side channels in both GF(256) implementations its Mode selector chose between - Mode.Table through operand-indexed log/exp tables, the AES T-table weakness, and Mode.Native through a Russian-peasant multiply that branched on each bit. Both are replaced by one branchless implementation, byte-for-byte identical over all 65536 operand pairs, so shares and reconstructed secrets are unchanged; the jdk1.4 overlay carries the same arithmetic. ShamirSecretSplitter.Mode no longer selects anything and is deprecated in favour of new mode-free factory methods. Separately, the arrays behind a split and its recovery were mis-sized and mis-indexed: the share array was sized by the secret's length rather than the requested share count, getSecret counted Lagrange products into a byte so recovery failed from 130 shares up, and splitAround and resplit took a share or secret of the wrong length without checking. All are now sized and checked, and a zero divisor is rejected rather than rewriting every share with zeroes.
- JcePBMac1CalculatorBuilder.build() took the PBKDF2 iterationCount out of an RFC 9579 PBMAC1Params directly, unlike every sibling PBE/PBMAC1 path in the tree, all of which already bound it before deriving a key. Since PKCS12PfxPdu.isMacValid dispatches an id-PBMAC1 MacData to this builder and the key must be derived before the MAC can be checked, a file with an attacker-chosen count pinned a CPU core running PBKDF2-HMAC before the unauthenticated file was ever rejected. The count is now bounded by org.bouncycastle.pbe.max_iteration_count, throwing OperatorCreationException when exceeded (CVE-2026-17508).
- SAKKE key decapsulation inverted the receiver identifier plus the KMS master secret modulo q with the variable-time BigInteger.modInverse; it now uses BigIntegers.modOddInverse. The sum was also passed in unreduced, and since a reduction does no work when the value already fits the modulus, whether one happened was a threshold predicate on the master secret - answered once per public identifier served and combinable across identifiers. The sum is now canonicalised with the new BigIntegers.modAdd, the public identifier reduced on the way in, and a master secret outside [1, q-1] rejected as a malformed key. The [z]P computations now go through ECAlgorithms.multiplySecret. Recovered shared secrets are unchanged.
- Locating the JRE's default trust store in BCJSSE was not done in a privileged block, so under a security manager the FilePermission was required of every protection domain on the call stack rather than of the provider alone. The read of the file was already privileged, but the File.exists() probes that find it were not - so in a container sandboxing application code SSLContext.getDefault() failed with "Default SSL algorithm not found in JRE", permanently, the outcome being cached in a static holder. The default key store path had the same gap. Locating, opening and closing both stores now run inside doPrivileged.
- The byte[] and InputStream constructors of ERSEvidenceRecord, and the byte[] constructor of ERSArchiveTimeStamp, could let an unchecked exception from ASN.1 decoding escape on malformed input, past their declared TSPException / ERSException contract. Evidence records are third-party artefacts parsed before any signature over them has been checked, so a caller that had correctly handled the documented exceptions still saw an unchecked one propagate. All three now report malformed input as an ERSException with the original preserved as its cause.
- EC scalar multiplication of a variable point by a secret scalar ran on the curve's default windowed-NAF multiplier, whose branch pattern, table indexing and doubling-run lengths all depend on the scalar. Every secret-scalar point multiplication now runs on the new constant-time multiplier via ECAlgorithms.multiplySecret. This is a hardening rather than a fix for a demonstrated attack; note that on curves without custom fixed-limb field implementations - the brainpool and GOST curves, or a caller-defined one - the underlying BigInteger field arithmetic can still vary with operand values.
- Sorting the elements of a SET was an insertion sort that re-derived an element's DER encoding every time it was shifted, so ordering N elements cost O(N^2) encodings. The sort is reached from getEncoded(ASN1Encoding.DER) and equals(), which for CMS covers the DER re-encode of the signed attributes performed before the signature has been checked. Each element is now encoded once and the encodings ordered with a stable O(N log N) sort: on 20,000 elements the re-encode drops from 1.9s to 7ms for descending input. The ordering produced is unchanged.
- Cramer-Shoup decryption raised the ciphertext components u1 and u2 to exponents carrying the long-term private key with bare BigInteger.modPow calls, and recovered the message through modInverse - neither constant-time, so a decryption oracle leaked timing information about the key. All three exponents are now blinded with a random multiple of p-1 and the inverse is gone, u1 to the power -z being computed as u1 to the power p-1-z. Separately u1 and u2 were not range-checked, so an all-zero ciphertext passed the correctness check and reached modInverse(0), raising an unchecked ArithmeticException; both must now lie in [2, p-2].
- The ZUC EIA3 message authentication codes accumulated the keystream contribution of each message bit inside a branch on that bit, so the time taken was proportional to the Hamming weight of the message - measured over a 2KB message, throughput varied by a factor of 3.7 (Zuc128Mac) and 5.2 (Zuc256Mac) between an all-zero and a random one. The contribution is now accumulated branchlessly by masking with the bit. MAC values are unchanged; the cost is now uniformly that of the previous worst case.
- The bcrypt round count in an encrypted OpenSSH v1 private key was used unbounded. It is read from the key's own kdfoptions and drives the KDF before anything about the key has been verified, and a round costs several milliseconds, so the 2^31-1 the wire format allows is worth CPU-months from a key file of a few hundred bytes - the only member of the PKCS#12 / BCFKS / BKS / PBES2 family with no bound at all. It is now capped by the new org.bouncycastle.openssh.max_rounds property, default 1048576. Reached only when a passphrase is supplied, so this is the key-import path (CVE-2026-17508).
- The OER decoder skips an extension it has no definition for by reading its declared length one byte at a time, and the loop ignored the -1 that InputStream.read returns at end of stream. That length is bounded only by 2^31-1 - the one length consumer in OERInputStream outside the decoder's allocation ceiling - so a ten-byte payload declaring a large unknown extension burned around 40 seconds of CPU per extension slot, and the parse then returned normally, recording nothing. The body is now consumed in bounded chunks and a truncated one rejected with an EOFException.
- The SNOVA signer's linear solve was not constant-time: performGaussianElimination searched downward for the first non-zero pivot, swapped rows when it found one lower down, and skipped the row-add when the factor was zero - three branches on a matrix derived from the private key and the per-signature vinegar. The elimination is now branchless, every lower row added under a mask that is all-ones only while the pivot is still zero, with the singular case tested once after the loop. Output is byte-for-byte identical across all 44 parameter sets. The only residual variable-time behaviour is the rejection-resample on a singular system, which is key-independent.
- The HPKE (RFC 9180) sequence number was advanced while computing the per-message nonce rather than after Seal/Open succeeded, as sec. 5.2 requires, so a ciphertext rejected by the AEAD tag check still moved the receiving context's counter on - after one forged or corrupted message, every subsequent genuine message failed to open. This is availability only, not nonce reuse, and the one-shot seal / open pair was unaffected. The counter now advances only on success, and the sec. 5.2 message limit is enforced rather than left as a comment.
- Prime-field Diffie-Hellman MQV (MQVBasicAgreement, reached through the JCE as the MQVwithSHA\*KDF and MQVwithSHA\*CKDF key agreements) raised a base built entirely from the values the other party supplied to an exponent carrying the long-term static private key, with a bare BigInteger.modPow. That exponent is now blinded with a random multiple of q - sound because every value in the base has been checked to lie in the order-q subgroup before it arrives, and q keeps the exponent the size it already was. MQVBasicAgreement now also accepts ParametersWithRandom so the blinding can use a caller-supplied source; agreed secrets are unchanged.
- The PBKDF2 keyLength carried in a BCFKS keystore and in an RFC 9579 PBMAC1-protected PKCS#12 file was used unbounded, even though the iteration count beside it is capped: it sizes the key derivation output, so an attacker-supplied value drove an arbitrarily long derivation before the MAC over that file had been checked, and the multiply by 8 to convert to bits overflowed, turning KeyStore.load into an unchecked NegativeArraySizeException escaping its declared IOException. The keyLength is now bounded at all six sites, with the bound applied before deriving (CVE-2026-17508).
- ASN1BMPString was the last ASN.1 primitive to size a buffer from the declared length before reading any content, allocating a char[] for the whole declared length up front - so an eight-byte header could drive an allocation as large as the parser's length bound and raise an OutOfMemoryError, an Error, escaping the IOException the parse API declares, and it worked nested inside any structure arriving off the wire. The content is now read through DefiniteLengthInputStream.toByteArray, as every other primitive already was (github #2338).
- KeyBoxByteBuffer.rangeOf checked its range with "end - start \< 0 || start \< 0", which a sufficiently negative end slips past: the subtraction overflows to a positive value (start = 1 with end = Integer.MIN_VALUE wraps to Integer.MAX_VALUE), clearing that guard and the buffer-limit check below it, so a 38-byte keybox file reached new byte[end - start] and allocated 2GB. end is now checked on its own. The keybox test's existing "End is negative" case passed on the subtraction alone and did not cover this, so a wrapping case was added alongside.
- The element-count check in org.bouncycastle.asn1.tsp.EvidenceRecord read "sequence.size() \< 3 && sequence.size() \> 5", a condition no value can satisfy, so the check never fired. RFC 4998 sec. 4 gives EvidenceRecord three mandatory fields (version, digestAlgorithms, archiveTimeStampSequence) and two optional ones, and the constructor reads getObjectAt(0), getObjectAt(1) and getObjectAt(size - 1) unconditionally, so a SEQUENCE carrying fewer than three elements raised ArrayIndexOutOfBoundsException instead of the IllegalArgumentException the getInstance contract documents. The check now reads "\< 3 || \> 5"; sequences of three to five elements are unaffected.
- PGPSecretKeyParser could not terminate on a truncated GnuPG extended key expression. The header loop exits only on reading a "Key" header, and consumeUntil returned void, so it could not distinguish the ':' delimiter from end-of-input and spun forever accumulating nothing. A zero-byte stream was the cheapest trigger of all, because isExtendedSExpression read -1 and reported "extended". End-of-input is no longer treated as an extended expression, and a header list that ends before the Key header is now rejected with an IOException.
- An MLS leaf_index is a uint32 on the wire held in a signed int, and NodeIndex(LeafIndex) doubled it with an int multiply, which wraps for any index at or above 2^30. The negative node index then compared as less than every signed bound, so LeafIndex.directPath - which has no bound check of its own - never reached the root and accumulated nodes until the heap was exhausted, and commonAncestor spun forever; an index of exactly 2^31 wrapped to node 0, aliasing a real leaf. The doubling is now unsigned long arithmetic and directPath bounds its argument. The decode constructor still accepts the full uint32 range, which the RFC 9420 test vectors require.
- MLS proposal validation for an external commit (a NEW_MEMBER_COMMIT sender) only counted the Remove proposals in the list - unlike the normal path, it never validated one - so a removed leaf index reached applyRemove straight from the wire, and one naming a leaf outside the tree escaped as an unchecked exception out of Group.handle instead of being rejected as an invalid proposal list. Both paths now share a bounds check on the removed index. The external path still cannot use the normal validateRemove, which additionally rejects self-removes: an external resync Commit legitimately removes the sender's own former leaf.
- RSA-KEM decapsulation raised the caller-supplied encapsulation to the private exponent with a bare BigInteger.modPow, bypassing the blinding every other RSA private-key operation in the library goes through - and a KEM recipient is exactly a decapsulation oracle, the attacker choosing the encapsulation and free to submit as many as it likes. Both sites, the lightweight RSAKEMExtractor and the JCE Cipher SPI reached from CMS KEMRecipientInfo, now exponentiate through RSABlindedEngine, which also applies the Lenstra CRT fault check and rejects an encapsulation not less than the modulus. RSAKEMExtractor gains a SecureRandom constructor, and the JCE SPI now honours the random supplied to Cipher.init. Derived secrets are unchanged.
- org.bouncycastle.crypto.params.ECCSIKeyGenerationParameters sized the random KSAK by the bit length of the curve coefficient a rather than of the curve order q, so on any curve with a = 0 - the Koblitz curves secp160k1, secp192k1, secp224k1, secp256k1 and others - the constructor asked for a 0-bit random value and threw IllegalArgumentException, making ECCSI key generation impossible there. The KSAK is a random secret in [1, q-1] (RFC 6507 sec. 4.2) and is now sized by the order's bit length. Curves where the two bit lengths coincide, the RFC's P-256 among them, are unchanged.
- BcPublicKeyDataDecryptorFactory.recoverSessionData, which declares throws PGPException, let an ArrayIndexOutOfBoundsException escape on a truncated X25519, X448 or ECDH encrypted session key: the PKESK parser imposes no minimum length on that field, and the lightweight decrypt path read the encoding before its length check. It now fails with the declared PGPException. The JCE decryptor derived the ECDH point length ahead of both its try and its own length check and leaked the same exception; it carries the same guard now, in the base class and in the jdk1.1 overlay.
- TlsUtils.readFully and readAllOrNothing sized their destination buffer from the requested length before reading anything, and that length comes straight off the wire, so three bytes of prefix committed a 16MB buffer per record before any of those bytes had arrived - at the start of a handshake, and so before any authentication. readFully(int, InputStream) is also public, where a caller-supplied 2^31-1 raised an OutOfMemoryError from a handful of input bytes. Both now read through Streams.readLenBytesFully, which grows its buffer as bytes are actually delivered.
- The raw JCA PBKDF2 provider did not bound the PBKDF2 iteration count, in either generateSecret(PBEKeySpec) or - the attacker-reachable case - AlgorithmParameters.init(encoded), reached when a Cipher decrypts a PBES2-protected structure whose parameters are parsed straight from untrusted input. Since PBKDF2 performs one PRF invocation per iteration, a count near 2^31 forced an unbounded stretching computation before use. Both paths now reject a count above org.bouncycastle.pbe.max_iteration_count (default 10,000,000), comparing as a BigInteger so a value beyond the int range cannot wrap past the check (CVE-2026-17508).
- The SRP-6a implementations raised values to exponents carrying private material with bare BigInteger.modPow calls: on the client the ephemeral a, the password-derived x and u\*x+a; on the server the ephemeral b; and in the verifier generator x again, the longest-lived secret in the protocol. Since a peer drives each exchange and can repeat it, the timing leaked information about them. Every one is now randomised with a random multiple of N-1, which leaves the results unchanged by Fermat. Both copies are covered - the lightweight agreement and the TLS SRP one - and SRP6VerifierGenerator gained an init() overload taking a SecureRandom.
- DTLS handshake reassembly tracked the not-yet-received ranges of a message in a list rescanned from the start on every fragment, and every interior fragment splits a range in two, so the cost was quadratic in the message length rather than in the data received: single-byte fragments at alternating offsets took a 128KiB message to 64K ranges and 78 seconds of CPU, spent before anything about the peer has been verified. The scan now starts from a binary search and the number of ranges is bounded at one per 512 bytes with a floor of 1024 - the same case now costs 25ms. Verified byte-for-byte against the previous algorithm over 20,000 randomised fragment sequences.
- OERInputStream.parse declares only IOException, and the pkix entry points that reach it propagate only that, but six fields taken straight from the encoding were used without a range check and so raised an unchecked RuntimeException past that contract, before any signature check: a CHOICE tag indexing the alternative list directly, a tag class other than context-specific, a length determinant through intValueExact, and an extension bitmap with a missing or sign-extended unused-bit count. All six are now IOException, which is what X.696 sec. 8.7 makes of an unknown alternative. An ENUM label lookup left on the production path is now inside its debug guard.
- org.bouncycastle.mime.Headers duplicated its header split and Content-Type interpretation between two of its three constructors and the copies had drifted, so Headers(InputStream, String) - the one BasicMimeParser and SMimeParserProvider use - raised unchecked exceptions rather than the IOException it declares for a header line with no ':', a multipart Content-Type with no boundary, a single-character boundary and a parameter with no '='. All four are now IOException. The same quoted-string strip was also silently wrong for a bare boundary, which RFC 2046 permits, so all three constructors now share one implementation. Separately, Headers(String, String) shadowed its own field, so getContentType() returned null for every instance built that way.
- The S/MIME canonicalisers walked nested multipart content with no depth counter, so the signed half of an inbound multipart/signed - entirely sender-controlled - could exhaust the thread stack, a StackOverflowError arriving at a depth of about 2500 from roughly 180KB of mail. There was a second, independent uncapped recursion in the multipart/signed content handler, with its own hand-maintained jmail copy, so a fix confined to SMIMEUtil would have left both. Both now stop at the new org.bouncycastle.mime.max_depth property, default 64, throwing MessagingException when exceeded.
- PGPPad.unpadSessionData read the pad count out of the RFC 3394 unwrapped session key without checking it against the buffer length. A count past the end makes the constant-time mask -1 at every index, so a uniform buffer satisfies the pad consistency check and reaches new byte[negative]: an unchecked NegativeArraySizeException in place of the declared PGPException, on the ordinary decrypt path of any client holding an ECDH subkey. Any uniform buffer of 8, 16, 24, 32 or 40 bytes works. The negative length is now folded into the same constant-time reject, and a buffer shorter than eight bytes refused up front.
- ArmoredInputStream.read() returned read(), calling itself, on reaching the ASCII-armor checksum line. The running CRC-24 is not reset between lines and the checksum was not required to be the last thing before the armor tail, so repeating one line whose value matches - "=twTO", the base64 of the CRC-24 initial value, which needs no data bytes at all - cost a stack frame per line and threw StackOverflowError from about 360KB of plain ASCII, escaping the catch (IOException) callers put around PGP parsing. A second checksum is now rejected, per RFC 9580 sec. 6.2.
- X500Name.hashCode() threw a NullPointerException for a name containing an RDN decoded from an empty SET, which any peer can encode: calculateHashCode took the RDN's first AttributeTypeAndValue without a null check, where its siblings for equals() and toString() both had one. An empty RDN now contributes nothing to the hash. hashCode() was additionally marking the value calculated before computing it, so once a style had thrown every later call quietly returned 0 - a single loud failure degrading into a silent source of hash collisions.
- ElGamal decryption raised the caller-supplied ciphertext component gamma to an exponent carrying the private key with a bare BigInteger.modPow, so a decryption oracle - which is what an ElGamal recipient is, the caller choosing gamma and free to submit as many ciphertexts as it likes - leaked timing information about the private exponent, the same shape RSABlindedEngine exists to close for RSA. The exponent is now blinded with a random multiple of p-1, leaving recovered plaintexts unchanged by Fermat. The multiple has to be of p-1 rather than of the subgroup order, since gamma need not lie in the order-q subgroup. A hardening rather than a fix for a demonstrated attack.
- HSSSigner.init and LMSSigner.init assigned only the key for the mode being set and left the other one from a previous init in place, so a signer initialised for verification still held the private key from an earlier signing init and would sign with it, and one initialised for signing would verify. Both keys are now cleared on every init, and calling the signer in the mode it was not initialised for raises IllegalStateException naming which init is missing rather than working off the stale key. Note the same pattern remains in the older pqc.crypto signers, while every signer added since already clears both.
- The JCE Diffie-Hellman key agreement performed its own modular exponentiation rather than going through DHBasicAgreement, so it did not pick up the blinding added there and the timing of the agreement still varied with our private value. It is now blinded the same way, with a random multiple of p-1, and the SecureRandom passed to KeyAgreement.init is kept and used for it where both init paths previously discarded it. Agreed secrets are unchanged.
- LMS private-key encodings now preserve a bounded top-of-tree cache alongside the existing seed material, so a decoded LMS/HSS private key avoids rebuilding the Merkle tree before its first signature - about thirty times faster for the h10 and h15 parameter sets. A standalone LMS key appends the cache after the master secret and stays version 0, so releases predating it still read the key; a multi-level HSS key announces it with encoding version 1 instead, its component keys sharing one stream. A third-party audit then established that almost none of the decoder's fields were validated: d is now bounded 1..8 as RFC 8554 sec. 6 requires, the index pair and q / maxQ are range checked against the tree size, and each cached interior node is recomputed from its children - a fixed 31 hashes per component key - with the node count required to be a complete top of tree so that cover is complete. The retry that reads a pre-HSS single LMS key no longer masks the original failure (github #2365, github #2414).
- XMSS and XMSS^MT private keys no longer write their BDS traversal state with Java ObjectOutputStream. Newly encoded keys carry a deterministic, versioned binary state whose node and collection lengths are checked against the XMSS parameters before allocation or use; for an XMSS-SHA2_10_256 key the state drops from 2193 bytes to 974. Keys carrying the legacy Java-serialized state remain readable through the restricted class allow-list. In the ASN.1 structures used for non-standard tree heights, bdsState is now a CHOICE of [0] legacy and [1] versioned binary, so the encoding in use is identifiable from the tag.
- The PQC PrivateKeyFactory chose its algorithm branch with a subtree test on the OID arc, which matches every leaf below it - including leaves the parameters table has no entry for - and then passed the null lookup straight into a constructor. A PKCS#8 PrivateKeyInfo naming such an OID escaped createKey with a NullPointerException past its declared IOException for fourteen of the eighteen arcs, and returned a key carrying null parameters for the other four; the OQS interop arc alone carries sixteen such declared-but-unimplemented OIDs. Each branch now dispatches on the parameters table itself, falling through to an unrecognised-algorithm IOException, and five public-key converter registrations with the same gap are corrected too.
- EdEC KeyFactorySpi.engineGeneratePublic read the algorithm discriminator byte from a malformed X509EncodedKeySpec before checking the encoding length, so very short Ed25519/Ed448/X25519/X448 public-key encodings leaked ArrayIndexOutOfBoundsException, and malformed full-length ones could leak runtime exceptions from the key-parameter constructors instead of the KeyFactory contract's InvalidKeySpecException. The base implementation and the jdk1.4, jdk1.11 and jdk1.15 overlays now guard the fixed-offset fast path and wrap decode failures.
- KeyAgreement.generateSecret(String) let an unchecked exception escape from BaseAgreementSpi for a key size it could not satisfy, past a method declaring only NoSuchAlgorithmException and InvalidKeyException: without a KDF the key can only be taken from the shared secret itself, and the copy was made without checking it would fit, so SM2 and SM9 above 128 bits, and plain ECDH on a curve below 256 bits for generateSecret("AES"), overran with ArrayIndexOutOfBoundsException. The request need not come from local code - JceKeyAgreeRecipient derives its key-encryption key with generateSecret(wrapAlg) read from the unauthenticated CMS message. Such a request now fails with a NoSuchAlgorithmException naming the requested and available sizes. The explicit "[keySize]" suffix was also parsed without validation and is now rejected when malformed.
- SM4 was absent from the key-size table that BaseAgreementSpi uses to size the key a JCE KeyAgreement derives, so generateSecret(alg) could not produce an SM4 key of the right length for any agreement. The name and the OIDs of the SM4 modes the provider implements now resolve to 128 bits. The practical effect is on CMS: an EnvelopedData that used key agreement with an SM4 key wrap could not be opened, failing outright with a KDF-based agreement and producing a KEK of the whole shared secret without one. sms4-xts is deliberately not listed. Note a caller relying on these names falling through to the entire shared secret now receives a 16-byte key.
- The scrypt cost guard in the PKCS#8 and PKCS#12 decryptor builders bounded only the cost parameter N and the block size r against org.bouncycastle.pbe.max_scrypt_memory, and never read the parallelization parameter p. RFC 7914 sizes scrypt's working memory as a 128\*N\*r byte V array plus a 128\*r\*p byte B array, so p drove an allocation the guard was not accounting for at all - a minimal N and r with p at the engine's own overflow ceiling passed the check and then allocated hundreds of megabytes. p is now validated and bounded against the same budget, separately from N so the previous limit is preserved exactly.
- The PBKDF2 keyLength bounding added for RFC 9579 PBMAC1 missed one call site: org.bouncycastle.pkcs.bc.PKCS12PBEUtils.createPBMac1Calculator, reached from PKCS12PfxPdu.isMacValid via the lightweight BcPKCS12PBMac1CalculatorBuilder, still derived a key sized directly from the attacker-controlled, unauthenticated PBKDF2Params.keyLength before any password or MAC check. It now goes through the same org.bouncycastle.pkcs.util.PKCS12Util.validateKeyLength bound as the JCE-side JcePBMac1CalculatorBuilder and PKCS12Util.calculatePBMAC1 paths (CVE-2026-17508).
- BLS12_381BasicScheme.keyValidate - and so every BasicScheme, MessageAugmentation and ProofOfPossession verify, which all gate on it - accepted a public key built on a foreign ECCurve that merely shares BLS12-381's field characteristic. The prime-order subgroup check trusts a point's own curve to name its cofactor, returning true outright when that cofactor is 1, so a point on a curve with a different equation and a cofactor forged to 1 passed despite not being a G1 point at all, letting it be registered as a signer contributing nothing to an aggregate signature. keyValidate now confirms the canonical G1 field, equation, order and cofactor first. Only reachable by direct construction on an explicit non-canonical curve, not through the standard compressed-point decoder (CVE-2026-71891).
- CMS AuthenticatedData accepted a message whose digestAlgorithm and authAttrs fields disagreed about whether authenticated attributes were present, which RFC 5652 sec. 9.1 pairs. The streaming parser has to choose how to compute the MAC before it reaches authAttrs, so it chose on digestAlgorithm alone: for a message with digestAlgorithm absent but authAttrs present it verified the genuine content MAC and then handed the attributes back through getAuthAttrs() as though they had been authenticated. An attacker able to modify a message in transit could insert an authenticated attribute - an ESSSecurityLabel, say - holding neither the key-encryption nor the content-MAC key. The in-memory path now rejects the mismatch at parse, and the parser cross-checks once authAttrs is read. A variant of CVE-2026-59642, which remained reproducible after that fix (CVE-2026-71888).
- Neither copy of PKIXCertPathReviewer applied X.509 name constraints to the end-entity certificate: checkNameConstraints() walked the path with a loop bound of index \> 0, which is what the CA-only steps want, but index 0 is the target certificate, so the permitted and excluded subtree checks of RFC 5280 sec. 6.1.3 never ran against the leaf. A chain whose leaf violated a NameConstraints extension imposed by its own issuing CA reported isValidCertPath() true with an empty error list, where CertPathValidator "PKIX" rejected the identical chain. Both copies now check every certificate including the target, waive the self-issued exemption for the final one, and skip the sec. 6.1.4 (g) accumulation step there (CVE-2026-71889).
- The MLS external-commit path let a joiner remove an arbitrary existing group member. Validation of an external commit's proposal list counted the proposals and bounded the removed leaf index, but never established that the removed leaf had anything to do with the joiner - RFC 9420 sec. 12.2 permits at most one Remove, "with which the joiner removes an old version of themselves". So any party holding the group's public GroupInfo, which is precisely what an external joiner is meant to be given, could commit a Remove naming any member's LeafIndex and take over their slot in the ratchet tree. The credential check that should have prevented this existed only in the gRPC interop harness, not in Group itself. Such a commit is now accepted only when the removed leaf's credential is identical to the joiner's own, compared by encoding rather than by getIdentity() (CVE-2026-71890).
- The high-level OpenPGP message API offered no way to bound how far a compressed data packet expands. PGPCompressedData has long carried getDataStream(long) for exactly this, but OpenPGPMessageInputStream always called the unbounded overload and OpenPGPPolicy exposed no corresponding property, so a caller on the recommended processor path had no way to set one - and counting bytes off the returned stream cannot help, the decompression having already happened by then. OpenPGPPolicy has gained getMaximumDecompressedDataSize(), applied per compressed data packet and raising StreamOverflowException when passed. The default is unbounded, so existing behaviour is unchanged.
- ShamirSplitSecret.divide(int) and multiple(int), which re-scale an existing share set in place, could silently overwrite every share with zeroes and irreversibly destroy the secret: GF(256) multiplication reduces its operand modulo 256, so a divisor or multiplier whose low eight bits are zero is the field's zero element, and divide() rejected only an exactly-zero divisor while multiple() checked nothing at all. Both now reject a value with (value & 0xFF) == 0 up front. In-range re-scaling is unaffected.
- The parameter-set specific HQC, NTRU+ and SMAUG-T KeyFactory implementations in the BCPQC provider accepted keys from a different parameter set of the same family - a factory obtained as "HQC-256" would import an hqc-128 key, returning a key object for the weaker set. Their shared base class checks the algorithm OID in an encoded key spec against the one the factory was constructed for, but these three overrode both import methods with copies that omitted the check. The overrides are removed, so all three inherit the checked path. This matters to a caller using a parameter-set specific factory as an import policy. Family-level factories are unchanged, as is the converter path used for certificate and PKCS#8 decoding.
- The CRL fetcher behind X509RevocationChecker still downcast the opened connection to HttpURLConnection, so a CRL Distribution Point naming any other protocol threw a ClassCastException out of a method declaring IOException / CRLException. That downcast was removed from the provider's copy of CrlCache in the 1.68 cycle (github #1867), but the pkix copy was left as it was; since its only caller catches Exception around the fetch, the effect was a distribution point quietly logged as ignored. The two fetchers are now identical, and the jdk1.4 overlay of the provider's copy carries the fix too.
- X509RevocationChecker downloaded CRLs from a certificate's CRL Distribution Points extension whenever the CRLs it had been given could not answer for a certificate, with no way for a caller to prevent it - unlike the provider's CertPath validator, which has always required the org.bouncycastle.x509.enableCRLDP property, and unlike what that property's own javadoc describes. The checker now honours it. **This is a behavioural change for anyone relying on the previous automatic fetch**: with the property unset it now behaves exactly as an unproductive fetch always did, so such callers should set it to "true" to keep the old behaviour.
- OcspCache.getOcspResponse read an OCSP response up to the length the responder itself declared in its Content-Length header, applying its own 32K ceiling only when that header was absent - so a responder, or anything able to answer in its place, that declared and sent hundreds of megabytes was read into the caller's heap. The declared length may now only narrow the read, never widen it. The ceiling is configurable through the new org.bouncycastle.ocsp.max_response_size property and its default is raised from 32K to 64K; a value of zero or less is ignored, so a mistyped value cannot turn the limit off.
- ArmoredInputStream parses the OpenPGP ASCII armor headers as the stream is constructed, and bounded neither the length of a header line nor the number of them, so merely wrapping an untrusted stream could exhaust the heap before the caller had read a byte - reachable both by a header line that never arrives at a terminator and by short lines that never stop arriving. Both are now capped, at 4096 bytes per line and 64 headers, each configurable through a new property; exceeding either raises ArmoredInputException. The equivalent accumulation in PemReader is deliberately left unbounded, a PEM body being legitimately able to run to gigabytes.
- Five parameter-set specific KeyPairGenerator implementations in the BCPQC provider ignored the parameter set named by the algorithm and generated keys for their family's default instead, so KeyPairGenerator.getInstance("HQC-256", "BCPQC").generateKeyPair() returned an hqc-128 key pair. The constructor took the parameter set but used it only to name the JCA algorithm, leaving the generator uninitialised, so generateKeyPair() took the branch hard-coded to the family default, with nothing reporting the substitution. All five now initialise from their own parameter set, and each refuses an initialize() naming a different one. The family-level generators are unchanged.
- Following on from the entry above, a sweep of every PQC family registering parameter-set specific generators found six more - SLH-DSA in the BC provider, and QRUOV, FAEST, HAETAE, SDitH and MQOM in BCPQC - which produced the right parameter set but would accept an initialize() naming a different one, silently re-pointing a generator at another level. All six now refuse it, as ML-KEM, ML-DSA and others already did. **This is a behavioural change for a caller that deliberately re-initialised a named generator.** Separately, SLHDSAKeyPairGeneratorSpi double-prefixed its algorithm name, returning "SLH-DSA-SLH-DSA-SHA2-128S"; keys and signatures were never affected.
- The AIMer, SMAUG-T and NTRU+ parameter set names were not registered as algorithm aliases in the BCPQC provider, so getInstance(spec.getName()) - the natural way to turn an AlgorithmParameterSpec into a service, and what the other sixteen PQC families accept - failed with NoSuchAlgorithmException. The spellings differ from the registered names only in punctuation ("aimer128f" against "AIMer-128f", "SMAUGT_MODE1" against "SMAUGT-MODE1", "NTRU+KEM768" against "NTRU+KEM-768"), so the mismatch was easy to hit and gave no hint as to the spelling wanted. Each parameter set name is now an alias across every service its family registers.
- A key's getAlgorithm() in the BCPQC provider did not always name a service the provider registers, so the standard round trip of KeyFactory.getInstance(key.getAlgorithm(), "BCPQC") failed for three families. Streamlined NTRU Prime keys reported the sibling family's "NTRULPRime", resolving to the wrong KeyFactory, and now report "SNTRUPrime". BIKE keys reported a parameter-set name where the family registers family-level services only, and now report "BIKE", with the parameter-set locked Ciphers checking the key's own parameter set instead so the lock is unchanged in effect. SPHINCS-256 keys report the algorithm's published name, which is now an alias of the SPHINCS256 services.
- Four PQC families disagreed with themselves about how a parameter set is spelled, their KeyPairGenerator taking its JCA algorithm name from the lightweight parameters object rather than from the name it was registered under - Falcon reporting "falcon-1024" where it is registered as FALCON-1024, SMAUG-T "smaugt_mode1" against SMAUGT-MODE1, and NTRU+ NTRU+KEM768 against NTRU+KEM-768. Each family now uses one spelling throughout, and each generator reports the name it was obtained under. **Both previous spellings continue to resolve**, being registered as aliases across every service of their families; only getAlgorithm() and the parameter set name change.
- The JCA/JCE provider classes for the pre-standardisation SPHINCS+ and Kyber have been removed from the BCPQC provider hierarchy, along with the unused org.bouncycastle.jcajce.provider.asymmetric.SPHINCSPlus mappings. Neither was listed in either provider's algorithm set, so none of the services they described had been obtainable through either; they were superseded by SLH-DSA and ML-KEM in the BC provider, which are registered and are what callers should use. The corresponding exports are dropped from both module-info descriptors. The lightweight implementations are untouched.
- The parameter-set specific HashML-DSA Signature services in the BC provider refused a pure ML-DSA key of their own parameter set, so a caller with a key obtained as "ML-DSA-65" and a signature as "ML-DSA-65-WITH-SHA512" met InvalidKeyException. FIPS 204 sec. 5 defines one key generation algorithm per parameter set and its keys carry no commitment to the pure mode over the pre-hash one, so the pure key was a perfectly good HashML-DSA key; the SPIs were comparing algorithm names, which differ by the suffix. The comparison is now against the parameter set. Signatures are unchanged. **The tolerance is one way only** - a key naming a HashML-DSA parameter set is still refused by the pure services (github #2397).
- The parameter-set specific SLH-DSA Signature services were not bound to their parameter set at all: all twenty four algorithm names, and their OIDs, were registered as aliases of the unparameterised service, so the name a caller asked for had no effect on which keys were accepted - Signature.getInstance("SLH-DSA-SHAKE-256S") would sign quite happily with an SLH-DSA-SHA2-128F key. This matters to a caller using the algorithm name as a policy gate. Each name and OID is now bound to its own parameter set, applying the same one-way pure / pre-hash rule as ML-DSA. **This is a behavioural change for a caller that relied on a named service accepting a key of another parameter set**; the unparameterised services are unchanged.
- Signature.setParameter(...) on any of the ML-DSA or SLH-DSA services threw NullPointerException when called before initSign / initVerify, out of a method declared to throw InvalidAlgorithmParameterException: applying a context means re-initialising the signer with the key the Signature holds, and the base engine went straight there without checking there was a key to re-initialise with. The context may now be set either side of initialisation, as the RSASSA-PSS parameters may be, and initialising no longer discards one set beforehand. Setting a context after initialisation produces exactly the signatures it did before (github #2396).
- An OCSP response carrying no nextUpdate could be cached and reused as though it stated a validity interval, so it went on answering for a certificate after the responder had newer information about it - after a revocation in particular - bounded only by garbage collection rather than by any interval the responder or caller had a say in. RFC 6960 sec. 4.2.2.1 says the opposite of what that assumes: an absent nextUpdate indicates newer information is available all the time. Such a response is still accepted from the responder but may no longer be served from the cache. Both the cached and stapled paths now also apply that section's other rule, that a response dated ahead of local time - beyond a 15 minute skew allowance - is unreliable.
- None of the javax.crypto.KEM encapsulators destroyed the SecretWithEncapsulation the mechanism handed them, so each left the mechanism's own session key live in the heap for as long as the Encapsulator was reachable - ML-KEM, HQC, NTRU, NTRU Prime and SM9 all affected. Clearing the derived key did not cover it, since getSecret() and getEncapsulation() hand back clones and only destroy() reaches the originals. Each encapsulator now destroys it in a finally block, after taking both values - the order matters, since destroy() clears the encapsulation too. Nothing observable changes for a caller.
- The KEM KeyGenerator services had the same missing key-size check as the javax.crypto.KEM ones described under Additional Features below: a spec built withNoKdf() and given a key size larger than the mechanism's session key overran the shared secret and threw ArrayIndexOutOfBoundsException out of generateKey(). The conventional 256-bit request failed that way for FrodoKEM's 976 parameter sets, whose session key is 192 bits. The check now sits in KdfUtil.makeKeyBytes, refusing the request with an IllegalArgumentException naming both sizes rather than quietly meeting it at the shorter length. The Cipher and KTS wrapping paths were never affected.
- The PKIX certification path builders kept the failure cause of a build in an instance field that was never cleared, so a CertPathBuilder reused for a further build could report a stale diagnostic - a build that found no path while recording no failure of its own reported the previous build's failure instead of "Unable to find certificate chain.". The field is now cleared at the start of each build, and the recursive search removes each certificate from its working path in a finally block, so every exit restores it for the next candidate.
- The BCJSSE provider now only computes active early key share groups for clients offering TLS 1.3+. Previously it was computed for all connections, which was mostly harmless, but could generate misleading log messages (at WARNING level) for servers or pre-TLS1.3 clients where the logged condition was irrelevant (github #2392).
- Initialising a BC signature, cipher or key-agreement service with a private key from another provider whose key material is not accessible - a hardware-backed key whose getModulus() or getS() throws, as an IBM CCA RSAPrivateHWKey does - let that provider-specific unchecked exception escape a method declared to throw only InvalidKeyException, so an mTLS handshake failed with a raw hardware error rather than the documented type. The key-parameter helpers that examine a key through a java.security.interfaces type now catch a failure to read its parameters and raise InvalidKeyException with the original chained as the cause. This does not let BC use a non-exportable hardware key; it makes the refusal in contract (github #1440).
- A TLS server that answered a client's "status_request" or "status_request_v2" extension stored the echo it sent in the session and replayed it on every abbreviated handshake that resumed it - announcing a CertificateStatus message that an abbreviated handshake never sends, and doing so whether or not the resuming ClientHello had offered the extension at all. RFC 5246 sec. 7.4.1.4 has a client abort with unsupported_extension over exactly that, so a resumption by a client that did not re-offer it failed outright. Both echoes are now dropped from the extensions replayed on a resumed handshake.
- DefaultKemEncapsulationLengthProvider.getEncapsulationLength() looked its argument up in a table of the KEMs whose encapsulation lengths are registered and dereferenced the result without checking it, so a CMS KEMRecipientInfo recipient using BIKE, NTRU+ or SMAUG-T - which register a key wrapping cipher but no length - got as far as the wrap and then failed with a NullPointerException naming nothing. The lookup now throws IllegalArgumentException naming the KEM's OID, as the sibling DefaultKemAlgorithmIdentifierFinder does (github #2398).
- AbstractTlsServer.notifyHandshakeBeginning() cleared the "status_request" extension recorded from the previous ClientHello but not "status_request_v2" or "trusted_ca_keys", which processClientExtensions assigns only when the ClientHello carries any extensions at all. A TlsServer driven through more than one handshake therefore carried both over, and a following ClientHello with no extensions had the server echo them from the earlier handshake's values - which RFC 5246 sec. 7.4.1.4 has a client abort over. Both are now cleared alongside "status_request".
- org.bouncycastle.pqc.crypto.aimer.AIMerSigner.verifySignature() read the signature at a fixed offset without first checking the buffer was long enough to hold one. A truncated or otherwise short signature therefore threw ArrayIndexOutOfBoundsException instead of returning false, which reached the caller unchecked out of Signature.verify() on the BCPQC "AIMer" services. Anything that is not exactly the parameter set's signature size is now reported as a failed verification, and a correctly formed signature is unaffected. This was the first half of the signed-message envelope problem described above, which the second half then removed the envelope itself for (github #2401, github #2403).
- The high-level OpenPGP certificate API accepted a third-party certification or trust delegation from any component key of the issuing certificate, without requiring that component to have been granted the authority to certify. Nothing checked for the RFC 9580 sec. 5.2.3.29 CERTIFY_OTHER flag, so a subkey bound only with SIGN_DATA - the online signing subkey of exactly the offline-primary arrangement those flags exist to express - could issue a user-id certification or a full-trust delegation that the API returned as a valid signature chain. This does not forge the primary key's signature; it lets a compromised restricted subkey act with the primary key's identity-issuing authority. Such a signature is now attributed only when made by the primary key or by a subkey holding CERTIFY_OTHER. Third-party revocations are deliberately left outside the rule, since declining to honour one would keep trust alive rather than withdraw it. Affects 1.81 through 1.85.2 (CVE-2026-71886).
- Signature.verify() on a malformed LMS signature threw an unchecked exception out of the lightweight API rather than reporting the problem the way the JCA does, so an empty, truncated or otherwise damaged signature reached the caller as IllegalStateException("cannot parse signature"), and one naming an OTS type other than the verifying key's as IllegalArgumentException. LMSSignatureSpi.engineVerify() now answers false for a signature it cannot parse, as ML-DSA, SLH-DSA, XMSS and XMSS^MT already did, and throws SignatureException for one it can parse but cannot process, which is the OTS type mismatch. Either way the accumulated message is cleared, so the signature object stays usable afterwards (github #2408).
- An XMSS signature carrying trailing data was accepted as valid. XMSSSignature.Builder.withSignature() read the index, randomness, WOTS+ signature and authentication path at their fixed offsets and ignored anything past them, so appending arbitrary bytes to a valid signature produced a second, different encoding that still verified. RFC 8391 sec. 4.1.8 fixes an XMSS signature at 4 + n + (len + h) \* n bytes, and the builder now rejects any other length the way XMSSMTSignature always has, which also covers the truncated case (github #2408).
- KeyPairGenerator.getInstance("XMSSMT").generateKeyPair() without a preceding initialize() threw IllegalArgumentException("layers must divide totalHeight without remainder"): the parameters used when uninitialised were height 10 with 20 layers, which is not a constructible XMSS^MT parameter set, leaving the default unusable. The default is now XMSSMT-SHA2_20/2_512 (RFC 8391 sec. 5.4). The same path in both the XMSS and XMSS^MT generators also left the returned key without a tree digest, so equals(), hashCode() and getTreeDigest() threw NullPointerException on a default-generated key; both now set it (github #2408).
- Kangaroo (KangarooTwelve / MarsupilamiFourteen) could not produce its output in more than one piece: KangarooBase.switchToSqueezing() never recorded that it had run, so doOutput() re-entered it on every call and the second failed trying to absorb into an already-squeezing sponge - neither a repeated doOutput() nor a doFinal() closing out a squeeze already begun was possible, both of which SHAKE, Blake3 and AsconXof support. The squeezing state is now recorded. Absorbing after a squeeze has begun is still refused (github PR #2409).
- The SRP-6a evidence-message checks compared the authenticator received from the peer against the locally computed one with BigInteger.equals, which returns as soon as it meets a differing word. M1 and M2 are keyed authenticators arriving from a peer that is not yet authenticated, so that early-out is a comparison timing oracle against a value the peer is trying to guess. Both copies - the lightweight agreement and the BCTLS one - now compare with Arrays.constantTimeAreEqual over fixed-width encodings. The J-PAKE MacTag check, which had the same shape, was given the same treatment. The accept/reject decision is unchanged (github PR #2406).
- Signature.setParameter(...) on the composite ML-DSA services threw NullPointerException when called before initSign / initVerify, the composite counterpart of the base-engine defect fixed for issue #2396: the composite SPI has its own engineSetParameter and went straight to re-initialising the component signatures without checking there was a key. The context may now be set either side of initialisation. Three further problems in the same method are fixed with it: a foreign parameter spec carrying a context had the context applied and was then reported as rejected, so a caller taking the exception at its word went on signing with a context it believed unset; getParameters() cached its result and a new context did not clear it; and on the generic COMPOSITE service a spec set before the key arrived threw from the absent digest (github #2412).
- The structural check on decoded ASN.1 UTCTime / GeneralizedTime content introduced in 1.85 gave no way through for the zone-less UTCTime "YYMMDDHHMMSS", so a single such field made the structure carrying it unreadable - a CMS SignedData whose signing-time attribute lacked its trailing "Z", a shape found in signatures in circulation, failed to load with "invalid UTCTime format". The value is not legal, X.680 sec. 47.3 making the zone mandatory, but ASN1UTCTime.getTime() has always carried a branch reading it as GMT. The new org.bouncycastle.asn1.allow_zoneless_utctime property admits it and nothing else; generation is unaffected and the value is still not DER. Separately, CMSSignedDataParser.getSignerInfos() now reports a SignerInfo that fails to decode as the CMSException it declares (github #2411).
- The BCJSSE key managers could not select an SM2 certificate for TLS 1.3: ProvX509KeyManager registers a TLS 1.3 EC public-key filter per named curve, but only for the NIST and Brainpool curves, so a key store entry on sm2p256v1 was never matched against the key type the sm2sig_sm3 signature scheme asks for, and a server configured for the RFC 8998 cipher suites failed the handshake despite holding a usable credential. The filter is now registered for curveSM2 on both the client and server side. The RFC 8998 profile still requires explicit configuration (github #2416).
- Signature.getInstance("XMSS" / "XMSSMT", "BCPQC").initSign(privateKey, random) threw ClassCastException: the two-argument JCA form wraps the key in a ParametersWithRandom, but XMSSSigner.init() and XMSSMTSigner.init() cast their argument straight to the key parameters type, so only the one-argument form worked - and the SPI keeps the random, so every later init on the same object wrapped as well. All four signers now unwrap and discard the random, as SPHINCS256Signer does; XMSS derives its randomizer from the key itself, so signatures are unchanged. The unwrap happens before init() branches, so the verification side takes the wrapper too.
- The BC "PKIX" CertPathValidator in the chain validity model (PKIXExtendedParameters.CHAIN_VALIDITY_MODEL) could not use the ISIS-MTT dateOfCertGen extension. CertPathValidatorUtilities.getValidCertDateFromValidityModel() passed the raw result of X509Certificate.getExtensionValue(), which is the DER encoding of the extnValue OCTET STRING, straight to ASN1GeneralizedTime.getInstance(), so any end-entity certificate carrying the extension failed validation with "Could not validate time of certificate." rather than having its issuer checked at the recorded generation time. The OCTET STRING is now unwrapped first, and the underlying decoding error is chained on the reported exception.
- OpenPGP AEAD decryption (SEIPDv2 and the v5 AEAD packet) still accepted a truncated message without reporting an error, by a route the 1.85 final-tag fix did not cover: truncation that leaves the enclosing packet length untouched raises an EOFException, which BCPGInputStream.nextPacketTag() reads as a clean end of message. Where the literal packet ended on an AEAD chunk boundary and the consumer read in increments smaller than one chunk, the final message tag was never reached, so the caller was given the authenticated chunks' plaintext with every following packet silently dropped - where RFC 9580 sec. 13.7 requires a clear error. That EOF is now re-thrown as a plain IOException, which nextPacketTag() does not launder; the legacy jdk1.1 overlay received this fix and the 1.85 one (CVE-2026-85515).
- The high-level OpenPGP API performed no integrity check at all on a truncated SEIPDv1 (MDC) message, releasing its plaintext with no error. Same cause as the entry above: IntegrityProtectedInputStream verifies the MDC from close(), and reached close() only by closing itself when a read returned -1, which a truncated message never produces - so PGPEncryptedData.verify() never ran and the recipient was handed CFB-decrypted plaintext on which nothing had been checked. OpenPGPMessageInputStream.close() now closes that stream itself, and IntegrityProtectedInputStream.close() was made idempotent as java.io.Closeable requires. The low-level API is unaffected (CVE-2026-85515).
- The recipient side of the CMS KEM path (RFC 9629 KEMRecipientInfo) let three sender-controlled fields escape as unchecked exceptions from methods declaring throws CMSException: a kekLength too large for an int reached intValueExact() before the range check that exists to reject it, a KEMRecipientInfo whose sequence size and optional ukm tag disagreed read its fields at the wrong index, and a wrap algorithm with no known KEK size threw from outside the catch at unwrap. All three are now CMSException. Separately, the recipient never compared the kekLength on the wire against the key size of the algorithm named in the wrap field, which RFC 9629 sec. 3 requires - a kekLength of 16 alongside AES-256-KW was accepted and the message decrypted; that mismatch is now refused before unwrapping. The malformed-content translation was also missing from three neighbouring entry points and has been added (github #2422).
- Signature.setParameter() on the RSA-PSS services rejected a PSSParameterSpec whose trailerField is not 1 - correctly, RFC 4055 sec. 3.1 fixing it at 1 - but reported it with an unchecked IllegalArgumentException where setParameter declares InvalidAlgorithmParameterException, and only after the spec's digest, MGF and salt length had already been assigned. A rejected spec was therefore half-applied: getParameters() reported parameters the signer was not using, and on an engine not yet initialised the next initSign built its signer from them, so a caller told the call had failed went on to sign with the parameters it believed refused. The unchecked type was reachable from data alone, X509SignatureUtil handing a certificate's decoded params to setParameter. The trailer field is now checked ahead of every assignment and reported as InvalidAlgorithmParameterException, as SunRsaSign does (github #2421).
- The PKCS#12 key stores let an unchecked exception escape KeyStore.setKeyEntry() and setCertificateEntry(), both of which declare only KeyStoreException: the two key their internal certificate map on a digest over the certificate's public key, and a certificate naming an algorithm the provider has no key info converter for has a null public key, so the digest step dereferenced null. Both had also stored the entry by then, leaving a rejected key or certificate behind under its alias. Both stores now require a resolvable public key before anything is stored and report a missing one as the KeyStoreException they declare; a zero-length chain is reported likewise. The jdk1.3 and jdk1.4 copies carry the same corrections (github #2419).
- Reading a prefixed (old style, non-one-pass) signed message through OpenPGPMessageProcessor threw a NullPointerException out of OpenPGPMessageInputStream.read() whenever the signer's certificate had not been supplied - the ordinary case of a message arriving before its sender's key has been fetched. In a prefixed message the signature precedes the literal data, so it can only be initialised once the issuer's key is known; the reader recorded such a signature with a null issuer and fed the message data to it regardless. Only a successfully initialised signature is now updated and verified (github #2417).
- Every classical signer assembled the signature component s with plain BigInteger arithmetic over the signing key - ECDSA, SM2, DSA, GOST 3410, ECGOST 3410, EC-NR, BIP 340 and DSTU 4145 - and while the inverse in each had already moved to the constant-time BigIntegers.modOddInverse, the multiplications and reductions around it had not. BigInteger.mod does an amount of work set by the quotient, so forming s answered a question about the long-lived signing key once per signature, and those answers combine over a run of them. All eight now go through BigIntegers.modMult, modAdd and the new modSubtract, which need their operands already reduced - so each hash-derived value is reduced on the way in, and DSAPrivateKeyParameters and GOST3410PrivateKeyParameters, which unlike the EC ones never range-checked x, now reject a key outside [1, q-1] at construction. Signatures are unchanged, reproducing the RFC 6979, GM/T 0003.2, BIP-340 and GOST R 34.10 vectors byte for byte.
- The XDH KeyFactory did not accept the JDK's own X25519 / X448 key specs. On JDK 11 and later BC's keys implement XECPublicKey and XECPrivateKey, so a caller can read the coordinate and scalar through the standard interfaces, but the reverse direction was missing - generatePublic(new XECPublicKeySpec(...)) failed with "key spec not recognized", and asking for either spec back reached a "not implemented yet" fall-through. A key could be exported through the standard interface but not re-imported through the standard spec. Both are now accepted and returned, through the same jdk1.11 hook that produces the XEC-implementing key classes, with the u-coordinate reduced modulo the field prime as RFC 7748 sec. 5 requires. Covered by a new multi-release test run by the test11 task.
- The GOST R 34.10-2001 / 2012 signer drew its per-signature nonce uniformly over the bit length of the group order and rejected only a draw of zero, where the 34.10-94 signer beside it already redraws anything at or past the order - so a larger draw was folded to k mod n, making the bottom of the range likelier than the top. On most named curves that costs nothing, but on the three whose order is about 0.61 of 2^256 a nonce fell below n/2 about 61% of the time rather than 50%, and a non-uniform nonce is the input a lattice attack on the signing key consumes. It is now redrawn until it is below the order. The 34.10-94 signer had the mirror of the gap and accepted a draw of zero, the single value that gives the signing key away outright; it is now redrawn too.
- org.bouncycastle.openpgp.api.DoubleBufferedInputStream has been removed. Present since 1.81 to withhold a trailing window of decrypted data, it was never referenced by anything in the library and did not work: read() returned the buffered byte unmasked, so every byte from 0x80 up came back negative and 0xFF came back as -1, which a caller reads as end of stream - data silently corrupted and then silently truncated. It also never filled its buffers, so the amount withheld was one read rather than the configured size. It is removed rather than repaired. Note the high-level API still hands version 1 (MDC) plaintext to a streaming caller before the integrity check runs at end of stream, so callers must not act on data until close() has returned without error (github #2424).

- The three X509CRL accessors let an unchecked exception escape when an indirect CRL carried an entry whose certificateIssuer extension did not decode to a directoryName: each re-parsed it with getNames()[0], raising ArrayIndexOutOfBoundsException for an empty GeneralNames and IllegalArgumentException for a first name that is not a directoryName, neither declared by X509CRL. Because the parse assumed the directoryName came first, a CRL naming it after another GeneralName - well-formed, GeneralNames having no ordering requirement - was refused as well, while X509CRLEntryObject read the same CRL correctly. All six call sites, including the deprecated X509CRLObject and the jdk1.1 and jdk1.3 overlays, now use that sibling's logic, promoted to a shared static (github #2425).

- Six OpenPGP signature subpackets whose body RFC 9580 defines as a fixed length did not enforce it at parse, deferring the check to an accessor that reported the wrong length as an unchecked IllegalStateException - Signature Creation Time, Key Expiration Time, Issuer Key ID, Exportable Certification, Revocable and Primary User ID; only Signature Expiration Time already checked. Because such a body inside a self-signature is content the signer signed over, a certificate carrying one verified as valid and only failed later in ordinary reader code, the keyserver re-export path included, which declares IOException rather than an unchecked exception. All six now check at parse, raising MalformedPacketException (github #2426).

- The provider's CertPath validator dropped the real reason a delegated CRL signer had been rejected and reported a misleading one in its place. RFC 5280 sec. 6.3.3 (f) requires an indirect CRL issuer's path to be anchored at the same trust anchor, so in a PKI with more than one root generation whose CRL signers share a Subject DN a CRL from another generation is correctly refused - but what reached the caller was "No CRLs found for issuer ... Searched 0 PKIXCRLStore(s)", describing neither the CRL examined nor the reason. Two things lost it: a guard that could never fire because the certificate's own issuer is always appended to the candidate set, and a fallback whose RecoverableCertPathValidatorException escaped with lastException unread. Both are corrected, and the bcpkix X509RevocationChecker with them. Which certificates validate is unchanged - this is diagnostics only (github #2427).

- The DTLS record layer silently discarded a record that failed to decrypt only when the failure was bad_record_mac; any other fatal alert raised while decoding it - decode_error for a body shorter than the cipher overhead, or decryption_failed for a block cipher body that is not a whole number of blocks - was rethrown, so the local connection failed and, through the fatal alert then sent, the peer's did as well. A record at the current epoch with any not-yet-seen sequence number reaches the decode and every other field is fixed or guessable, so one off-path forged datagram could tear an established association down at both ends. RFC 9147 sec. 4.5.2 and RFC 6347 sec. 4.1.2.7 both list invalid length among the records that SHOULD be silently discarded. Every fatal alert the cipher raises except internal_error is now discarded.

- Composite ML-DSA signing and verification of an empty message produced, and rejected, bytes no conforming implementation would accept. The SPI hands its components their parameters - the combination's domain separator as the ML-DSA context, and the per-combination PSSParameterSpec - from a priming step reached only from the two engineUpdate overloads, and signing an empty message calls neither. So BC disagreed with itself over whether the caller wrote update(new byte[0]) or nothing at all, the no-update spelling of each being the non-conforming one. The priming now also runs at the top of engineSign and engineVerify. Signatures over a non-empty message are unchanged.

- A signature context longer than 255 bytes was accepted by the composite ML-DSA services and silently truncated: len(ctx) travels in the message representative as a single byte, which draft-ietf-lamps-pq-composite-sigs sec. 4.1 requires an error above, so a 256-byte context was written as length zero. BC signed happily and round-tripped with itself because both sides truncated identically, while a conforming implementation must refuse to produce or check the same signature. The composite design routes around the base ML-DSA check, that component being initialised with the always-short domain separator. setParameter now rejects an over-long context by every route into it.

- A composite ML-DSA Signature object was left unusable by a malformed signature: engineVerify raises SignatureException for a signature too short to split at the ML-DSA component length, and did so before clearing the accumulated message, so the next update() appended to the stale bytes and every subsequent verify on that object returned false for no visible reason. The pre-hash digest is now reset in a finally on both engineSign and engineVerify, as the SLH-DSA and LMS services do. The failure direction was a false rejection throughout.

- A SecureRandom supplied by the caller was ignored by both composite ML-DSA entry points that take one. KeyPairGeneratorSpi.initialize(spec, random), whose only documented purpose is supplying one, forwarded it to a component only where the algorithm table held a non-null key generation spec - never the case for the ML-DSA half of any of the 18 combinations, nor the EdDSA half, so on the two Ed25519 combinations it reached neither component. The table now carries a spec for every component. Separately, the composite SignatureSpi did not override engineInitSign(PrivateKey, SecureRandom), so the caller's random was parked where nothing consulted it; it is now passed down to each component signer.

- Fourteen HashMLDSA composite algorithm names and OIDs, superseded when the scheme moved to the IANA arc, were still advertised by an API that could not then use them: the OIDs were never in the pairings map so no service was ever registered, yet they remained keys in the key-generation and name maps and names in DefaultSignatureAlgorithmIdentifierFinder - find("HASHMLDSA44-RSA2048-PSS-SHA256") handed back an AlgorithmIdentifier that JcaContentSignerBuilder then failed on. Those names and entries are removed; the OID constants remain, so an existing certificate carrying one still parses as it did.

- Composite ML-DSA services declared SupportedKeyClasses and SupportedKeyFormats attributes that were built and never passed to a provider registration, so JCA key-class filtering did not work for any of them. They are now published on the 37 composite Signature services and on the shared composite KeyFactory. Alongside this, several pieces documenting a superseded draft revision have been corrected or removed - engineSign's javadoc, the KeyFactory javadoc, an unused canonical-name table, a drifted second column of component key sizes and a main()-only harness for the old revision. bcpkix's openssl CompositeKeyTest was in no AllTests suite and so had never run; it is registered now.

- DefaultAlgorithmNameFinder knew none of the composite algorithms, so getAlgorithmName() on a composite certificate, CRL or SignedData returned the dotted OID string and every human-facing display of a composite algorithm was a number. All 30 are now named - the 18 Composite ML-DSA combinations and the 12 Composite ML-KEM ones - spelled exactly as the provider registers the corresponding service, so the name the finder hands back is one getInstance accepts. The finder and its test are locked together by an entry-count assertion.

- The composite ML-KEM implementation carried the same three defects that were fixed on the composite ML-DSA side in this release, the two packages having been written from the same template: the caller's SecureRandom reached no component for any of the 12 parameter sets, and neither half of the two XDH sets; the SupportedKeyClasses and SupportedKeyFormats attributes were built and never registered, so JCA key-class filtering did not work; and a wrapped key shorter than the composite encapsulation was not rejected before use, Arrays.copyOfRange zero-padding it so decapsulation ran on a padded encapsulation and the failure surfaced naming something other than the truncation. All three are corrected, along with a never-read column in the component size table and an unreachable ECDSA branch.

- The RFC 9579 PBMAC1 integrity MAC on a PKCS#12 file bounded the file's own PBKDF2 keyLength only from above, so a PFX declaring a keyLength of one or two octets was accepted and its MAC verified against a key short enough to brute-force - letting an attacker who does not know the password get a PFX of their own construction accepted, rather than merely failing the check. RFC 9579 sec. 9 asks for the other bound and sec. 5 has the length match the HMAC output size. The new PKCS12Util.validateMacKeyLength applies a 20-octet floor on the five paths that derive a PBMAC1 MAC key. The existing validateKeyLength is deliberately left alone, since it also validates the PBES2 content-encryption keyLength, where 16 octets is AES-128 (github #2431).

- JcePBMac1CalculatorBuilder named the wrong OID in the algorithm identifier it generates: the PBMAC1 keyDerivationFunc field identifies the key-derivation function and so carries id-PBKDF2, where the builder emitted id-PBES2 - the encryption scheme's OID - beside otherwise correct PBKDF2-params. BC's own readers take the parameters without consulting that OID, so BC verified its own output and the mistake went unseen, but BcPKCS12PBMac1CalculatorBuilder does consult it and rejects anything else, so a PFX MACed through the JCA builder could not be verified through the lightweight one. The builder now emits id-PBKDF2; reading stays deliberately lenient.

- The PKCS12-PBMAC1 keystore asked PBKDF2 for a 256-octet MAC key against an HMAC-SHA-512 message-authentication scheme, four times the size of the key that scheme uses. RFC 9579 sec. 5 says the derived key "SHOULD be the same size as the HMAC function output size", so the keystore now asks for 64, as does the default on PKCS12StoreParameter.pbmac1WithPBKDF2Builder(). Nothing was weaker for the extra length. Reading is unaffected, the length being taken from the file. The builder's setKeySize() parameter, named keySizeinBits but always used as octets, is renamed keySizeInOctets - no behaviour or signature change - and PBMAC1WithPBKDF2Builder, which had no javadoc at all, is now documented.

- The three argument doFinal(byte[], int, int) on TupleHash and ParallelHash ignored the requested output length when binding the L parameter, encoding right_encode of the object's configured output size instead. NIST SP 800-185 sec. 5.3 step 4 and sec. 6.3 step 4 make L both the value encoded into the message and the number of bits squeezed, so a 32 byte and a 64 byte request encoded the same L and then read different amounts of one output stream - the shorter result being a prefix of the longer, contradicting the property sec. 5.1 and sec. 6.1 state outright for both functions. The requested length is now the L parameter, as it already was in KMAC. This changes the output for any caller passing an outLen other than the configured digest size; the two argument doFinal and doOutput are unaffected, as are the BC provider's TupleHash / ParallelHash MessageDigest services.

- The jdk1.3 and jdk1.4 legacy overlays of PKCS12KeyStoreSpi, and the jdk1.4 overlay of PKCS12PBMAC1KeyStoreSpi, wrote to System.out when KeyStore.load() met a PKCS#12 bag or content type they do not process, printing the bag's object identifier and then an ASN1Dump of its contents. The base implementation reports the same condition through java.util.logging, so bcprov-jdk14 and bcprov-jdk13 were the only builds in which loading a PFX could write the contents of an unrecognised bag to the console, with no way to route or suppress it. The jdk1.4 PKCS12KeyStoreSpi overlay now mirrors base; the jdk1.3 overlay and the shared PBMAC1 one, which the jdk1.3 build also compiles and so cannot use java.util.logging, drop the diagnostic. The jdk18on artifacts were never affected.

### 2.2.3 Additional Features and Functionality

- BIP340Signer can now be initialised from an AsymmetricCipherKeyPair, through the new init(boolean, AsymmetricCipherKeyPair) overloads. BIP-340 signing needs the public point twice and derived it with a d'\*G multiplication every time; a caller that already holds the public key can now supply it and skip that, which measures about twice as fast since the two fixed-base multiplications are very nearly the whole cost of a signature. The public key is not checked against the private one, as checking it means performing the multiplication being avoided. The point is also now derived once per init() rather than on every signature. Signatures are unchanged (github #2420).

- BCJSSE: the new org.bouncycastle.jsse.useNamedGroupsOrder boolean system property (Properties.JSSE_USE_NAMED_GROUPS_ORDER) sets the default behaviour for TLS 1.3 server named group selection, applicable when no BCSSLParameters are set (in which case BCSSLParameters.useNamedGroupsOrder takes precedence). Set to true, connections of an SSLContext default to having a TLS 1.3 server select the key share group by its own named group order rather than the client's. Read per-SSLContext-init rather than once per class load.
- The XMSS and XMSS^MT implementation (RFC 8391, with the SP 800-208 parameter sets) has been promoted from org.bouncycastle.pqc.crypto.xmss into org.bouncycastle.crypto, following ML-KEM, ML-DSA, SLH-DSA and LMS: key parameters in crypto.params, generators in crypto.generators, XMSSSigner and XMSSMTSigner in crypto.signers, and the engine classes in crypto.signers.xmss. The crypto.util key factories now cover the XMSS OIDs in both the RFC 9802 and legacy forms. One behavioural difference: the promoted signers implement org.bouncycastle.crypto.Signer rather than StateAwareMessageSigner, so the one-shot generateSignature(byte[]) methods are not present, and an exhausted key raises crypto.ExhaustedPrivateKeyException, which the pqc one now extends. All encodings are unchanged and each implementation verifies what the other signed.
- XMSS and XMSS^MT are now algorithms of the BC provider as well as of BCPQC. BouncyCastleProvider has carried the key info converters for some time, so a certificate or PKCS#8 key naming one could be parsed, but the KeyFactory, KeyPairGenerator and Signature services were only in BCPQC - so an application installing only BouncyCastleProvider could read an XMSS key and then not sign with it. The names and OID aliases are the same in both providers, and both drive the same SPI classes.
- org.bouncycastle.pqc.crypto.xmss is deprecated in favour of the promoted implementation above and is scheduled for removal in the next release; it is otherwise unchanged and still carries its own test suites for this release. The two implementations hold their signature index in independent objects, so a single stateful private key must be driven through one of them and not both.
- The BCFKS keystore now honours a write-side iteration count property, org.bouncycastle.bcfks.store_it_count, the counterpart of the PKCS#12 one added earlier in this cycle: it sets the PBKDF2-HMAC-SHA512 iteration count used for the integrity MAC key, the store encryption and the entry key-encryption keys when a store is written without a BCFKSLoadStoreParameter naming its own KDF. The default remains 51,200; a value outside 1 .. 5,000,000 is ignored, the upper bound being the read-side cap so a file written under the property can always be read back.
- The LMS / HSS implementation (RFC 8554) has been promoted from org.bouncycastle.pqc.crypto.lms into org.bouncycastle.crypto, following ML-KEM, ML-DSA and SLH-DSA: key parameters in crypto.params, generators in crypto.generators, LMSSigner and HSSSigner in crypto.signers, and LMSContext and the engine in crypto.signers.lms. The crypto.util key factories now cover id-alg-hss-lms-hashsig, and the BC provider's LMS services use the promoted classes throughout. Two behavioural differences: the signers implement org.bouncycastle.crypto.Signer rather than MessageSigner, though the one-shot forms remain - mixing them with a message already buffered is refused with IllegalStateException before any one-time key is spent - and an exhausted key raises the new crypto.ExhaustedPrivateKeyException, which the pqc one now extends. All encodings are unchanged and each implementation verifies what the other signed.
- org.bouncycastle.pqc.crypto.lms is deprecated in favour of the promoted implementation above and is scheduled for removal in the next release; it is otherwise unchanged and still carries its own test suite for this release. The two implementations hold their signature index in independent objects, so a single stateful private key must be driven through one of them and not both. In the JCE layer, LMSKeyGenParameterSpec and the already-deprecated LMSParameterSpec gain a constructor and accessors taking the promoted types, the existing ones being deprecated alongside the package rather than repointed.
- The new org.bouncycastle.pkcs12.store_it_count property sets the PBE iteration count the PKCS12 keystore uses when writing a file, the write-side counterpart of the existing max_it_count. The default is unchanged - 600,000, twice that for the integrity MAC - but until now there was no way to ask for anything else, and the count was raised from 51,200 in 1.85, which multiplies the cost of writing or reading a keystore by about twelve. Lowering it is only worth doing where something other than the passphrase carries the file's confidentiality. A value outside 1 .. 2,500,000 is ignored. The same change corrects a long-standing divergence in the legacy Ant distributions, whose jdk13 and jdk14 jars were writing at 1,024 iterations - the figure PKCS#12 shipped with in the 1990s - and never took the MAC count from a file they had loaded.
- OpenPGP secret keys whose private key material is held outside the key - on a hardware token - are now supported, following draft-dkg-openpgp-external-secrets. SecretKeyPacket recognises the External S2K usage octet and its locator hint, PGPSecretKey exposes isExternalKey() and getExternalKeyLocatorHint(), and a decryption backend is plugged into the high-level API by registering a PublicKeyDataDecryptorFactoryProvider with OpenPGPMessageProcessor. On the lightweight side the raw private-key operation is isolated behind BcPublicKeyCryptoCallback, so a subclass routes only the RSA decryption or the ECDH/X25519 agreement to a device while inheriting all packet parsing, KDF and key-unwrap logic; JceExternalPublicKeyDataDecryptorFactoryBuilder is the JCA analogue. Note the External S2K usage octet is provisional - the draft records it as "TBD (252?)" and IANA has not assigned it.
- A new module, bcpgsc (org.bouncycastle.openpgp.smartcard), provides an OpenPGP smart-card API on top of the external-secret-key support: listing cards across pluggable backends, uploading key material, and decrypting messages with a card-held key. Two backends ship - a YubiKey backend built on the YubiKit libraries, and an in-memory simulator for testing without hardware. The YubiKit libraries are a compile-only dependency, so the published bcpgsc jar carries no third-party runtime dependency; an application using the YubiKey backend must add them to its own classpath.
- org.bouncycastle.openpgp.operator.PGPKeyPairGenerator gained named convenience methods for the three brainpool curves RFC 9580 sec. 9.2 permits for OpenPGP - generateBrainpoolP256r1ECDHKeyPair / generateBrainpoolP384r1ECDHKeyPair / generateBrainpoolP512r1ECDHKeyPair and the matching ECDSA variants - alongside the existing NIST P-256/P-384/P-521 methods. The generated ECDH keys carry the per-curve KDF hash and KEK symmetric algorithm required by sec. 11.5.1, which the key-pair generator tests now assert for the brainpool and the NIST curves alike.
- Further extended key usages are now available as KeyPurposeId constants: id-kp-secureShellClient and id-kp-secureShellServer (RFC 6187 sec. 2.2.2, id-kp 21/22), id-kp-cmcArchive (RFC 6402 sec. 2.10, id-kp 29) and id-kp-bundleSecurity (RFC 9174, id-kp 35).
- The two RFC 4556 (PKINIT) extended key usages are now available as KeyPurposeId constants: id-pkinit-KPClientAuth (1.3.6.1.5.2.3.4, sec. 3.2.2) as KeyPurposeId.id_kp_pkinitClientAuth and id-pkinit-KPKdc (1.3.6.1.5.2.3.5, sec. 3.2.4) as KeyPurposeId.id_kp_pkinitKdc. Note these sit under the Kerberos id-pkinit arc rather than the PKIX id-kp arc, and are distinct from the Microsoft smartcard logon usage already available as id_kp_smartcardlogon.
- org.bouncycastle.math.ec.ECConstantTimeMultiplier is a new constant-time variable-point scalar multiplier: a fixed window with signed-odd-digit recoding, so the iteration and doubling counts are independent of the scalar, with table entries fetched through ECCurve.createCacheSafeLookupTable's masked scan. It works over both prime and binary curves (the point must lie in the subgroup of the given, odd, group order) and returns exactly the point the existing multipliers do - only the timing profile differs. Use it via the new ECAlgorithms.multiplySecret(p, k) / multiplySecret(p, k, order), or install it on a curve with ECCurve.Config.setMultiplier.
- org.bouncycastle.util.BigIntegers.modAdd(M, X, Y) is a new constant-time modular addition for X and Y already in [0, M): the sum is formed at a fixed width and reduced by subtracting M unconditionally under a mask, so neither the running time nor the memory access pattern depends on the values. It is the companion to the existing modOddInverse for the step before an inversion - X.add(Y).mod(M) is not a safe way to get there, since a reduction does no work when the value already fits the modulus, so a sum that crosses the top of M is distinguishable from one that does not. Operands outside [0, M) are rejected rather than reduced.
- org.bouncycastle.util.BigIntegers.modMult(M, X, Y) is its companion for a product, again for X and Y in [0, M) but requiring an odd M: it multiplies in Montgomery form over a fixed number of words, so every loop runs a value-independent number of times and no index depends on the operands. A product is up to twice the width of M, so unlike a sum it cannot be reduced by one conditional subtraction. The quantities derived from the public modulus alone are computed with BigInteger, as they reveal nothing, and kept between calls. This is what lets a whole chain of order arithmetic be done without BigInteger.mod ever seeing a secret - every classical signer now assembles s this way (see Defects Fixed above).
- org.bouncycastle.util.BigIntegers.modSubtract(M, X, Y) completes the set, for X and Y in [0, M): the difference is formed at a fixed width and brought back into range by adding M unconditionally under a mask, the mirror of what modAdd does with a subtraction. X.subtract(Y).mod(M) is not a safe way to reach it, a negative value costing the reduction more work than a non-negative one, so whether the difference underflowed is distinguishable - and that is a comparison between the two operands, which where one is public is a threshold predicate on the secret one. Operands outside [0, M) are rejected.
- Support has been added for C509 certificates - the CBOR encoding of X.509 defined in draft-ietf-cose-cbor-encoded-cert-20. A deterministic CBOR reader/writer (RFC 8949 sec. 4.2, the new org.bouncycastle.cbor package in bcutil) underpins new value types in org.bouncycastle.cbor.c509 for C509 certificates, certification requests and templates, private key structures, C509PEM and COSE_C509, covering both natively signed structures and invertible CBOR re-encodings of DER X.509, where conversion is gated on the re-encoding reproducing the input DER byte for byte. bcpkix adds operator-based holder and builder classes with bc and jcajce verifier providers, and ESTService.getC509CertificationRequestTemplate(). The draft is still subject to change, so the API should be regarded as provisional until the RFC issues.
- The org.bouncycastle.jce.exception package (ExtException and its ExtCertPathValidatorException / ExtCertPathBuilderException / ExtCertificateEncodingException / ExtIOException subclasses) is deprecated. It existed only to attach an exception cause on pre-1.4 JVMs, which the supported runtimes now do natively; the provider cert-path and X.509 generator code now throws the standard java.security.cert exceptions, using new SecurityExceptions factories where a Java-1.4-safe cause attach is still needed. Messages and the certPath / index carried by CertPathValidatorException are unchanged; callers that caught the concrete Ext\* subclasses should catch the standard supertype instead.
- The RFC 5280 sec. 6.1.3/6.1.4 valid-policy-tree node type and its tree-manipulation helpers were previously triplicated across the provider's cert path validator, the provider's cert path reviewer and the PKIX revocation checker's reviewer. The node is now single-sourced as the public org.bouncycastle.jcajce.PKIXPolicyNode with the shared tree operations in PKIXPolicyTreeUtil, and all three stacks delegate to them; org.bouncycastle.jce.provider.PKIXPolicyNode is retained as a compatibility subclass. Behaviour is unchanged.
- org.bouncycastle.util.BigIntegers.createRandomBlindingMultiple(BigInteger, SecureRandom) returns a random multiple of a group order, for adding to a private exponent so that the exponent a variable-time BigInteger.modPow sees differs on every call. DSASigner carried this as a private helper and now calls the shared one, computing the same value and drawing from the supplied random in the same order. The javadoc records the premise the caller owns: the multiple must be of an order the base actually has - q only where the base is known to lie in that subgroup, otherwise p-1. Passing q for a base outside it silently returns the wrong answer, and no known-answer test catches it.
- The RFC 5280 sec. 6.3.3 CRL scope rules - the (b)(1) cRLIssuer check, the (b)(2) issuing distribution point checks, the (c)(2)/(c)(3) delta CRL consistency checks and the (d) reasons intersection - were previously maintained as duplicate implementations in the two RFC3280CertPathUtilities classes. They are now single-sourced in the new org.bouncycastle.asn1.x509.PKIXCRLValidator, a pure-ASN.1 companion to PKIXNameConstraintValidator reporting violations through the new checked CRLValidatorException; both cert path implementations delegate to it, so future corrections land once. Behaviour and exception messages are unchanged.
- Added an example (org.bouncycastle.asn1.x500.examples.X500NameStyleExample) showing how to build a custom X500NameStyle that relaxes the RFC 5280 commonName length bound, so a Distinguished Name with a CN longer than 64 characters can be parsed from its string form.
- The HPKE (RFC 9180) implementation in org.bouncycastle.crypto.hpke now supports the post-quantum KEMs ML-KEM-512/768/1024 (draft-connolly-cfrg-hpke-mlkem, KEM ids 0x0040-0x0042) and the X25519/ML-KEM-768 hybrid X-Wing (draft-connolly-cfrg-xwing-kem, KEM id 0x647a) via the corresponding HPKE.kem\_\* constants. These KEMs are not authenticated KEMs, so only the base and psk modes are available with them (github #2351).
- FrodoKEM can now be used as a recipient KEM in CMS EnvelopedData / AuthEnvelopedData via the RFC 9629 KEMRecipientInfo structure, following draft-chen-lamps-cms-frodokem. DefaultKemEncapsulationLengthProvider now knows the encapsulation lengths for all eight FrodoKEM / eFrodoKEM parameter sets under the ISO/IEC 18033-2 arc, which JceKEMRecipientInfoGenerator previously lacked. Per the draft the 976 parameter sets are keyed with AES-Wrap-192 and the 1344 sets with AES-Wrap-256, in both cases deriving the key-encryption key with HKDF-SHA256.
- CMS RFC 9629 KEMRecipientInfo generation now supports user keying material (UKM). JceKEMRecipientInfoGenerator.setUserKeyingMaterial(byte[]) populates the optional ukm field and folds the same bytes into the CMSORIforKEMOtherInfo KDF input, so the derived key-encryption key is bound to the UKM; the existing unwrapper (which already reconstructs the otherInfo from the received field) round-trips it unchanged. The generate side previously hard-coded an absent ukm. When no UKM is set the encoding is unchanged (the field remains absent).
- Composite ML-KEM (draft-ietf-lamps-pq-composite-kem) can now be used as a recipient KEM in CMS EnvelopedData via the RFC 9629 KEMRecipientInfo structure. A KEM Cipher backed by the composite KEM combiner is registered for all twelve composite parameter sets, and DefaultKemEncapsulationLengthProvider now knows their encapsulation lengths, so wrapping and unwrapping to a composite recipient work exactly as they do for ML-KEM and FrodoKEM. The composite provider previously registered no Cipher, so CMS wrapping to a composite recipient failed with "No such algorithm".
- KEM (RFC 9629 KEMRecipientInfo) recipients can now be used with CMS AuthEnvelopedData via the new org.bouncycastle.cms.jcajce.JceKEMAuthEnvelopedRecipient, the AuthEnveloped counterpart of JceKEMEnvelopedRecipient: it decapsulates the key-encryption key and verifies the AEAD authentication tag, so ML-KEM, FrodoKEM and Composite ML-KEM recipients work with AEAD content encryption (for example AES-256-GCM). Previously only EnvelopedData supported KEM recipients.
- The PQC private keys ML-DSA, ML-KEM, SLH-DSA, FrodoKEM and Classic McEliece now honour the JCA javax.security.auth.Destroyable contract. Previously destroy() fell through to the interface default, which throws DestroyFailedException, leaves isDestroyed() false and leaves the full secret recoverable through getEncoded() - so there was no way to erase these comparatively large private keys from the heap through the JCA API. destroy() now zeroizes the underlying key material, the lightweight parameter classes themselves being Destroyable, and the secret-bearing accessors throw IllegalStateException("key destroyed") afterwards. As the arrays may be shared with keys derived from the original, destroying one invalidates those too (github #2366).
- EC and RSA private keys now honour the Destroyable contract as well, extending the PQC support above to the classical algorithms, along with the underlying ECPrivateKeyParameters, RSAKeyParameters and RSAPrivateCrtKeyParameters. These hold their values as immutable BigIntegers, so unlike the byte[]-backed PQC keys they cannot be zeroized in place - destroy() drops the internal references and zeroizes any cached PKCS#8 encoding. Afterwards the secret-bearing accessors throw IllegalStateException, Java-serializing fails with an IOException rather than a leaked unchecked exception, and a get racing a destroy() only ever returns the intact value or throws. The public components remain accessible, hashCode() is stable across destruction and a destroyed key is equal only to itself (github #2366).
- The remaining private key types now honour the Destroyable contract, completing the work above (github #2366). The stateful hash-based keys - LMS/HSS, XMSS and XMSS^MT - zeroize their secret material while keeping the identifier, public seed, root, index and cached tree nodes, so getIndex() and the public key stay available; a signature attempt with a destroyed key is refused before a one-time index is spent, and shards split off before it was destroyed are unaffected. The BigInteger-backed classical keys - DSA, DH, ElGamal, GOST R 34.10-94, the two ECGOST variants and DSTU 4145 - follow the EC/RSA shape, dropping the private value reference while the domain parameters remain. In every case destroy() previously threw DestroyFailedException and left the full secret recoverable through getEncoded() (github #2432).
- Four NIST Lightweight Cryptography AEAD engines are faster, with bit-for-bit identical output verified against the published KAT vectors: ElephantEngine's Spongent permutation and PhotonBeetleEngine's PHOTON-256 MixColumn now use precomputed spread tables over flattened state (roughly 9x and 10x on large messages), RomulusEngine's SKINNY-128-384+ state and tweakey arrays were flattened to flat byte arrays (5.8x on HotSpot C2, 1.5x on GraalVM CE), and GiftCofbEngine's GIFT-128 PermBits became a branchless SWAR bit-transpose, a JIT-dependent trade at 1.26x on GraalVM CE but 14% slower on HotSpot C2. PhotonBeetleDigest and RomulusDigest share the permutations and gain the same. On constant-time behaviour, GIFT-COFB deliberately uses no data-indexed table so it still makes no secret-dependent memory access, and the PhotonBeetle and Elephant spread tables are indexed by the same secret state nibble or byte their existing S-box tables already index in the same round - though Elephant's table is larger than the S-box it subsumes, so a cache-line-granular observer learns more bits of that byte per lookup than before.
- generateCbom (gradle/cbom.gradle) now inventories the public lightweight API as well as the JCA service tables, so algorithms that ship with no JCA registration - J-PAKE, SRP-6a, OWL, HPKE, BLS12-381, RSA-KEM, ECCSI, SAKKE, BIP340, the SP800-90A DRBGs, Argon2, bcrypt, the KDFs, cSHAKE, the NIST lightweight-cryptography finalists and the rest - now appear in the CBOM. Public concrete implementations of the core primitive interfaces become assets automatically, a class counting as a generic construction rather than an algorithm only when a public constructor takes another core primitive (HMac(Digest), CMac(BlockCipher)), so a newly added public lightweight algorithm cannot silently miss the inventory. Every asset now carries a bc:api property recording whether it is reachable through the JCA providers or only through the lightweight API, and lightweight assets name their defining classes in a bc:classes property.
- SM2Engine.decrypt and the GOST28147, DSTU7624, DESede and RC2 key-wrap engines sized their output as new byte[inLen - overhead] without first checking the ciphertext was at least that overhead, so a short attacker-supplied ciphertext or wrapped key threw NegativeArraySizeException / ArrayIndexOutOfBoundsException instead of the declared InvalidCipherTextException. The engines now reject an under-length input with InvalidCipherTextException, matching the guard the IES, RFC 3394 and RFC 5649 engines already have.
- Four more length-validation guards across the lightweight crypto API reject wrong-length or truncated input up front rather than leaking an unchecked exception; valid-length input is unaffected. The AIMer (org.bouncycastle.pqc.crypto.aimer) private- and public-key parameter constructors reject keyData whose length is not the parameter set's secret / public key size, with IllegalArgumentException. LMSSignature.getInstance rejects trailing data after an LMS signature, making the parse non-malleable. ISO9796d2Signer guards its verify against an RSA-recovered block shorter than the header it must contain, rather than indexing past it. DANEEntry.isValidCertificate (org.bouncycastle.cert.dane) guards against a short or null DNS record rather than throwing ArrayIndexOutOfBoundsException.
- Added support for the SM9 identity-based cryptographic algorithms (GM/T 0044-2016) - digital signature, key encapsulation, public-key encryption and key exchange - built on an R-ate pairing over a 256-bit Barreto-Naehrig curve. SM9 is identity-based: a trusted Key Generation Centre holds a master key pair per scheme and derives each user's key deterministically from the user's identity, so there are no certificates and a sender or verifier forms the counterparty's public key from the published master public key and the identity alone. The lightweight classes follow the standard package layout - SM9Signer, SM9KEMGenerator / SM9KEMExtractor, SM9Engine, SM9KeyExchange and the master key-pair generators and parameter classes, with the curve, extension-field tower and pairing arithmetic in org.bouncycastle.math.ec.sm9 - and the provider exposes them through the GM family as Signature.SM9, Cipher.SM9, KeyGenerator.SM9-KEM (KEM.SM9-KEM on JDK 21+), KeyAgreement.SM9, KeyPairGenerator.SM9-SIGN / SM9-ENC and KeyFactory.SM9. Encryption offers both GM/T 0044.4 data-encapsulation modes and emits the GM/T 0080-2020 SM9Cipher structure; the two-round key exchange uses the KeyAgreement API's two-phase form with an SM9KeyExchangeSpec, and the optional GM/T 0044.3 key-confirmation tags, which that API has no channel for, remain available from the lightweight SM9KeyExchange only. User-key derivation runs its modular arithmetic through BouncyCastle's constant-time helpers and its scalar multiplications through a fixed-point comb in G1 and a fixed-iteration Montgomery ladder in G2, and every algorithm is verified against the GM/T 0044.5-2016 worked examples.
- An SM9 user private key can now be rebuilt through KeyFactory.SM9 from a stored encoding without access to the master private key, closing a gap against the lightweight API. A user key's PKCS#8 encoding alone does not determine a usable key - signing additionally needs the signature master public key and the identity, decryption the encryption master public key, the identity and the hid - so the new org.bouncycastle.jcajce.spec SM9SigUserPrivateKeySpec and SM9EncUserPrivateKeySpec carry that context alongside the encoding, and generatePrivate accepts either while getKeySpec hands the same spec back. This covers key-exchange user keys too, which a party receiving its key from the KGC rather than deriving it in process could otherwise not use at all: SM9EncPrivateKeyParameters gains fromEncodedExchangeKey and the spec an exchangeKey flag. The encoding does not record which usage the key was derived under, so the usage on an imported key is the importer's claim.
- The SM9 user keys now carry the identity (and, for a public key, the master public key) they were derived from, so a caller need not track that context alongside the key the way earlier versions required. org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters gains getIdentity(), matching the encryption side which already carried it, and SM9SigPrivateKeyParameters.fromEncoded now takes an identity alongside the master public key (both methods unreleased in this cycle, so this is not a compatibility break). On the JCA side four new org.bouncycastle.jcajce.interfaces capability interfaces - SM9SigUserPrivateKey, SM9SigUserPublicKey, SM9EncUserPrivateKey and SM9EncUserPublicKey - expose the same data on the provider's existing user-key classes.
- The GM/T 0081-2020 SM9 encryption and signature message syntax content types are now OID constants on org.bouncycastle.asn1.gm.GMObjectIdentifiers - sm9_pkcs7 (arc 1.2.156.10197.6.1.4.4) and its data, signedData, envelopedData, signedAndEnvelopedData, encryptedData and keyAgreementInfo branches - the SM9 counterpart of the GM/T 0010-2012 sm2_pkcs7 constants already present. Note that, unlike the SM2 arc, the structures these OIDs name are modelled on PKCS#7 but are not interchangeable with it: a GM/T 0081 SignedData keeps the PKCS#7 field order and tags while replacing certificates [0] / crls [1] with ibcSysParamsPublishInfos [0] / irls [1], so org.bouncycastle.asn1.pkcs.SignedData parses it and silently mislabels those two sets, and its SignerInfo identifies the signer by an identity-based Identifier rather than an IssuerAndSerialNumber and carries an SM9Signature where PKCS#7 has an EncryptedDigest OCTET STRING.
- Added support for RFC 9850, the SSLKEYLOGFILE format, so that a capture of a test TLS connection can be decrypted by an analyser such as Wireshark. BouncyCastle reports the secrets and does not store them: an application implements the new org.bouncycastle.tls.keylog.TlsKeyLog interface, whose single log(label, clientRandom, secret) method receives one RFC 9850 sec. 2 record at a time, and decides for itself on encoding, destination and access control. The implementation is named by the org.bouncycastle.tls.keylog.class property in the JVM's java.security file, read as a security property rather than a system property; the named class must be public, implement TlsKeyLog and have a public no-argument constructor, and its type is checked before it is constructed, so naming some other class is not a way to have arbitrary code run. If the property is unset nothing is loaded and no secret leaves the library. Reported are CLIENT_RANDOM for (D)TLS 1.2 and earlier and the handshake, application and exporter secrets for TLS 1.3; because the reporting sits in the key schedule itself, it covers the low-level (D)TLS API and the BCJSSE provider equally. This capability ships only in a new artifact, bctls-klog: the standard bctls jar contains none of it and no property will give it any, RFC 9850 sec. 1.1 asking that a deployed binary not be able to disclose its own keys at all, so obtaining connection secrets requires deliberately replacing bctls with bctls-klog, which must not be done in production. bctls-klog keeps the module name and packages of bctls so that it drops straight in, and is deliberately absent from the BOM as the two are alternatives rather than companions; its BCJSSE provider reports itself as "Bouncy Castle JSSE Provider Version 1.0.25 (Key Logger)" so a running JVM says which of the jars it has installed.
- KeyPurposeId constants for the three Extended Key Usage purposes RFC 9509 sec. 3 defines for 5G Network Functions: id_kp_jwt (id-kp 37, signing the JWT Claims Set of a Client Credentials Assertion), id_kp_httpContentEncrypt (id-kp 38, encrypting JSON objects in HTTP messages between Security Edge Protection Proxies) and id_kp_oauthAccessTokenSigning (id-kp 39, signing OAuth 2.0 access tokens for service authorization). The matching human-readable names are also registered in X509CertificateFormatter so the new EKUs print symbolically.
- SMAUG-T post-quantum key encapsulation mechanism (Module-Lizard / MLWE+MLWR), per the SMAUG-T v1.2.0 reference specification. The lightweight implementation in org.bouncycastle.pqc.crypto.smaugt covers all four parameter sets - smaugt_mode1, smaugt_mode3, smaugt_mode5 (NIST security categories 1/3/5) and smaugt_modet (TiMER, the bandwidth-optimised D2 variant) - and is KAT-tested against the reference distribution's vectors, 100 cases per set. JCE plumbing is registered through BCPQC (KeyPairGenerator, KeyFactory, KeyGenerator, Cipher key wrap/unwrap, SmaugTParameterSpec, the SmaugTKey interface and the BC key classes), four BC-arc OIDs cover the SubjectPublicKeyInfo / PrivateKeyInfo wire form, and BouncyCastleProvider.loadPQCKeys() registers a key factory against each so the standard BC provider can decode SMAUG-T-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain. The decode paths validate their input lengths up front, so a malformed key or encapsulation fails with an IllegalArgumentException at decode time rather than an ArrayIndexOutOfBoundsException later during encapsulation or decapsulation.
- Server-side OCSP stapling with the org.bouncycastle.tls API is now documented and covered by an example. The protocol support has been in place for some time - AbstractTlsServer echoes a client's "status_request" (RFC 6066 sec. 8) or "status_request_v2" (RFC 6961 sec. 2.2) extension, and the server protocols then send whatever TlsServer.getCertificateStatus() returns as a "certificate_status" message - but the callback's contract was not spelled out. Its javadoc, and that of AbstractTlsServer.allowCertificateStatus() / allowMultiCertStatus(), now describe when the callback is reached, how SecurityParameters.getStatusRequestVersion() selects between a single ocsp response and an ocsp_multi list ordered against the certificate chain, and that TLS 1.3 does not use this path. A new misc-module example, org.bouncycastle.tls.examples.OCSPStaplingServerExample, runs both variants end to end; for the BCJSSE provider see the entry below. See github issue #1157.
- Server-side OCSP stapling with the org.bouncycastle.tls API now also works in TLS 1.3, where it previously had no protocol support at all: RFC 8446 sec. 4.4.2.1 replaces the "certificate_status" handshake message with a "status_request" extension on the CertificateEntry carrying the certificate each response answers for, and TlsServerProtocol now assembles those itself from the same TlsServer.getCertificateStatus() callback the earlier versions use. Both shapes the callback may return are accepted - an ocsp status answers for the end-entity certificate, an ocsp_multi status answers positionally - and an entry the server has itself given a "status_request" extension is left as it stands, so an implementation already doing this by hand is unaffected. A response too large for the entry's 16-bit extension length is dropped rather than stapled, since letting one through would cost the handshake rather than just the staple. The wire form is now created and read through TlsExtensionsUtils.createStatusRequestExtension13 / readStatusRequestExtension13, which the BCJSSE provider also goes through. See github issue #1157.
- Client-side OCSP stapling with the org.bouncycastle.tls API now works in TLS 1.3, where TlsServerCertificate.getCertificateStatus() had always answered null: that value is set from the "certificate_status" message, and RFC 8446 sec. 4.4.2.1 sends no such message, carrying each response in a "status_request" extension of the CertificateEntry holding the certificate it answers for instead. The client now reads them as the Certificate message arrives and hands them back through the new TlsServerCertificate.getCertificateStatusAt(int), one per certificate of getCertificate(), null where that certificate was left unstapled - the same reading as the positional ocsp_multi list of TLS 1.2 and earlier. Two consequences: TlsServerCertificate has gained a method, so an implementation of that interface outside BC will not compile until it adds one (BC constructs the only implementation itself, so a caller merely receiving one is unaffected); and a server that mis-staples in TLS 1.3 now fails the handshake with a decode_error alert where the bytes previously went unread. A staple the client did not ask for is still ignored, and the BCJSSE client now shares this one implementation rather than carrying its own (github #1485).
- org.bouncycastle.operator.DefaultAlgorithmNameFinder now names KEM algorithm OIDs, which it previously did not do for any KEM at all - getAlgorithmName() handed back the OID string unchanged. Added are ML-KEM (FIPS 203, the three NIST OIDs) and, on the ISO/IEC 18033-2 arc the BC provider registers them under, all eight FrodoKEM and all sixteen Classic McEliece parameter sets; BouncyCastle's own pre-standard arcs for those two families are deliberately left unnamed, as those parameters are to be phased out. Names follow the canonical form of the matching lightweight parameter class, so they are also the names the provider registers the algorithms under. NTRU and HQC remain unnamed.
- org.bouncycastle.operator.KemAlgorithmIdentifierFinder and its DefaultKemAlgorithmIdentifierFinder implementation are the KEM counterpart of SignatureAlgorithmIdentifierFinder, turning a KEM algorithm name into the AlgorithmIdentifier that names it in a SubjectPublicKeyInfo, a CMS KEMRecipientInfo (RFC 9629) or a CMP KemCiphertextInfo - previously a caller had to assemble that identifier from the OID constants by hand. Names are matched without regard to case and cover the same set the name finder now names, so the two directions round-trip; an unrecognised name raises IllegalArgumentException rather than returning null, and a new hasAlgorithm(String) - added to the signature and digest finder implementations as well - tests for support without catching. Every identifier returned has an absent parameters field, so compare received identifiers with AlgorithmIdentifier.areEquivalent rather than equals. A new parent interface, org.bouncycastle.operator.AlgorithmIdentifierFinder, carries the shared find(String) contract for the three finders that behave alike, requiring only the method its subinterfaces already declared; MacAlgorithmIdentifierFinder stays outside it, as it returns null for an unrecognised name instead. DefaultDigestAlgorithmIdentifierFinder joins that contract: its name lookup now throws IllegalArgumentException where it used to return null - its other two overloads are untouched, so find(AlgorithmIdentifier) still returns null as github #1767 relies on - and it now folds case like the other three, which only widens what matches.
- org.bouncycastle.jcajce.provider.util.SecurityExceptions gained an invalidAlgorithmParameterException(String, Throwable) factory, for the same reason as its siblings: java.security.InvalidAlgorithmParameterException only grew a cause-taking constructor in Java 5, so code that has to compile for the legacy Java 4 distributions attaches the cause through initCause instead. Use the factory rather than rolling that call at the throw site.
- The BCJSSE provider now treats the ML-KEM based named groups as FIPS approved, and offers the hybrids among them by default. FipsUtils.isFipsNamedGroup answers true for X25519MLKEM768, MLKEM512, MLKEM768 and MLKEM1024 as well as the two SecP hybrids it already accepted - the key establishment in each is ML-KEM (FIPS 203), and in the X25519 hybrid the approved component supplies the shared secret the X25519 half is combined with - so a provider constructed in FIPS mode no longer filters any of them out. NamedGroupInfo's default candidate list, which applies when jdk.tls.namedGroups is not set, gains SecP256r1MLKEM768 and SecP384r1MLKEM1024, appended so the classical groups keep their existing preference. The pure ML-KEM groups are deliberately **not** in that list, following TLS working group feedback that a key exchange should retain a classical component: they are available in FIPS mode and out of it, but have to be asked for through jdk.tls.namedGroups or BCSSLParameters.setNamedGroups. curveSM2MLKEM768, x25519 and x448 remain outside the FIPS set. A new test, org.bouncycastle.jsse.provider.test.TlsFipsTest, drives a TLS 1.3 handshake through the FIPS mode provider for each of the six groups.
- FrodoKEM and Classic McEliece are now reachable through the javax.crypto.KEM API (JDK 21, JEP 452), which previously only ML-KEM, SM9, NTRU, NTRU Prime and HQC were: the standard BC provider registers KEM.FRODOKEM and KEM.CMCE, plus one parameter-set locked service for each of FrodoKEM's eight and Classic McEliece's sixteen ISO/IEC 18033-2 sets. As with the other KEMs the implementations live in the multi-release jar's version 17 tree and are gated on SpiUtil.hasKEM(), so on a JDK where javax.crypto.KEM is absent nothing is registered. Note FrodoKEM's session key size follows the parameter set - 192 bits for the 976 sets, 256 for the 1344 sets - so a KDF-less KTSParameterSpec asking for more bits than the set produces is refused with an InvalidAlgorithmParameterException naming the set and both sizes rather than being quietly shortened, javax.crypto.KEM validating encapsulate()'s range against secretSize(). The same now applies to everything else a KTSParameterSpec can carry that a KEM cannot honour, each of which previously escaped as an undeclared unchecked exception: a key size that is not a positive whole number of bytes, an unserviceable KDF algorithm identifier, and an absent key algorithm name. The validation, algorithm-name reconciliation and secret-key derivation are shared as new KdfUtil methods rather than duplicated per KEM, with behaviour and exception text unchanged.
- NTRU LPRime, NTRU+ and SMAUG-T are now reachable through the javax.crypto.KEM API as well, which completes the BCPQC KEMs: each already had Cipher, KeyGenerator, KeyFactory and KeyPairGenerator services and only the KEM one was missing. NTRU LPRime gets the family level KEM.NTRULPRIME matching the SNTRU Prime counterpart registered beside it, NTRU+ gets KEM.NTRUPLUS and SMAUG-T KEM.SMAUGT, each with one parameter-set locked service per set, and NTRULPRimeParameters and SmaugTParameters gain getEncapsulationLength() so the encapsulating side derives the size from the same place the extractor does. Note the NTRU+ decapsulator constructs its extractor per call: NTRUPlusEngine keeps one SHAKE instance in a field, so sharing one across the concurrent decapsulate calls javax.crypto.KEM permits returned shared secrets that did not match the sender's. The spec validation added for FrodoKEM and Classic McEliece now applies to every KEM in the provider except SM9, whose own KDF produces the shared secret at whatever size was requested; the checks that do carry over - an absent key algorithm name, a non-positive key size - are applied by KEM.SM9-KEM itself.
- The new org.bouncycastle.x509.CRLDP_protocols property is an optional whitelist of the protocols a CRL Distribution Point may name, applied by the CrlCache behind both the provider's CertPath validator and X509RevocationChecker before any connection is opened, and ahead of the cache, so an entry already held for a distribution point is no way around it. It is a comma separated list matched without regard to case - "http,https,ldap" refuses a distribution point naming ftp, file, jar or anything else the JVM happens to have a URL handler for, with a CRLException naming the protocol. Unset or empty, the default, leaves the protocol unrestricted: RFC 5280 sec. 4.2.1.13 requires a distribution point URI to name a protocol but does not restrict which, so this is a policy for deployments wanting a narrower set rather than a new default. Note the fetch it governs only happens where org.bouncycastle.x509.enableCRLDP is set (see Defects Fixed above).
- The Gradle build now checks Android compatibility with AnimalSniffer: each published module's base (Java 8) classes are verified against the Android API level 26 (Android 8.0) platform signature, so a reference to a java.* / javax.* API absent from that platform - the class of regression behind the BigIntegers.intValueExact NoSuchMethodError seen on older Android (see Defects Fixed above, github #2369) - fails the build rather than reaching a consumer's device as a runtime error. Only the base classes are checked, since the multi-release overlays are selected by JDK version and never load on Android. A small allow-list covers the intentionally platform-absent references: the optional JNDI-based fetchers (the LDAP CRL and certificate stores and the DANE fetcher), inert on Android as it ships no JNDI, and the legacy bcmail S/MIME content handlers' java.awt.datatransfer.DataFlavor reference, which cannot be dropped while javax.activation 1.x's ActivationDataFlavor extends it - Android consumers should use bcjmail, which carries no such reference (github #242). Based on the initial implementation in github #336.
- Classic McEliece can now be used as a recipient KEM in CMS EnvelopedData / AuthEnvelopedData via the RFC 9629 KEMRecipientInfo structure. DefaultKemEncapsulationLengthProvider now knows the encapsulation lengths for all sixteen parameter sets standardised under the ISO/IEC 18033-2 arc, which JceKEMRecipientInfoGenerator previously lacked - a Classic McEliece recipient failed the wrap - while DefaultAlgorithmNameFinder and DefaultKemAlgorithmIdentifierFinder already carried the parameter set names. Unlike ML-KEM and FrodoKEM there is no CMS profile for Classic McEliece, so the key-wrap algorithm is the caller's choice; the round-trip tests pair mceliece460896 with AES-Wrap-192 and the level 5 sets with AES-Wrap-256, keying the wrap with HKDF-SHA256.
- BCJSSE: the provider now offers server-side OCSP stapling, completing for the JSSE layer what the previous entry describes for the low-level TLS API. With the boolean system property jdk.tls.server.enableStatusRequestExtension set to true - default false, as in SunJSSE, since enabling it has the server make outbound OCSP requests on behalf of whoever connects to it - a BCJSSE server answers a client's "status_request" (RFC 6066 sec. 8) and "status_request_v2" (RFC 6961 sec. 2.2) extensions, sending a certificate_status message for TLS 1.2 (preferring an ocsp_multi list covering the chain) and a per-CertificateEntry "status_request" extension for TLS 1.3 per RFC 8446 sec. 4.4.2.1. Responses are fetched over HTTP from the responder named by each certificate's Authority Information Access extension - or from jdk.tls.stapling.responderURI under jdk.tls.stapling.responderOverride - subject to the org.bouncycastle.ocsp.max_response_size ceiling, and cached per SSLContext. At most one request is in flight per certificate however many handshakes are waiting on it, a failed lookup suppresses further attempts for a short interval, and a handshake's wait is bounded by jdk.tls.stapling.responseTimeout, a missing staple being an optimisation forgone rather than a handshake failure. The server does not verify what it relays; that is the receiving client's part. On the client side BCExtendedSSLSession.getStatusResponses() now returns TLS 1.3 staples positionally against the certificate chain, which makes a client stricter about what a server sends: an extension carrying anything RFC 8446 sec. 4.4.2.1 does not admit there now fails the handshake with a decode_error alert, where previously these bodies were not read at all. Clients that do not want to request staples can clear jdk.tls.client.enableStatusRequestExtension; the TLS 1.2 client path is unchanged. See github issue #1157, and #1485 for the client-side TLS 1.3 read.
- TlsPeer.getHandshakeTimeoutMillis() is now also honoured by the transport-agnostic blocking TlsClientProtocol / TlsServerProtocol stream API, completing what 1.85 provided only for the (BC)JSSE blocking-socket path (see above). A peer returning a non-zero value has the handshake abandoned with a TlsTimeoutException once the deadline has passed since the handshake began, checked at each record boundary; because a caller-supplied InputStream has no timed-read primitive, a peer that stalls part way through a record still blocks in the read itself, so bounding that still requires the transport's own read timeout - which the (BC)JSSE provider already supplies for blocking sockets, restoring the caller's SO_TIMEOUT once the handshake concludes. A handshake interrupted part way keeps the deadline armed across the interruption, so retrying cannot extend the total budget. The default behaviour is unchanged (AbstractTlsPeer returns zero, meaning no timeout), and the non-blocking API is left to the caller's own I/O loop (issue #1666).
- The Merkle Tree Certificate operator bindings org.bouncycastle.cert.plants.MTCContentSigner and MTCSignatureVerifierProvider (certificate mode) now follow Section 7.2 of draft-ietf-plants-merkle-tree-certs for any subtree: the entry index is taken from the certificate serial, the inclusion proof is evaluated in full and the MTCProof extensions enter the leaf hash, where previously both were hard-wired to a two-entry subtree with the entry at index 0; MerkleTreeCertificateValidator rejects a signatureValue BIT STRING with unused bits per Section 7.2 step 2; and the subtree primitives are now checked against the accumulated test vectors of the draft's Appendix C.
- org.bouncycastle.cert.plants.MerkleTreePrimitives now generates Merkle Tree Certificate proofs as well as verifying them: computeMerkleTreeHash() computes the RFC 9162 Merkle Tree Hash over a range of entry hashes, generateSubtreeInclusionProof() the RFC 9162 PATH inclusion proof of an entry within a subtree, and generateSubtreeConsistencyProof() the SUBTREE_PROOF algorithm of draft-ietf-plants-merkle-tree-certs Section 4.4.1 - the one Section 4 algorithm the class did not previously cover. Their output is accepted by the existing verification methods, so an issuer or log no longer has to bring its own tree code. Each generator comes in two forms: one over an in-memory List of entry hashes, and one over the new MerkleTreeNodeSource interface, through which a production log whose tree lives in storage supplies the full-subtree node hashes it already keeps - at most one per tree level per proof element - so proofs can be generated over a tree of any size without holding it in memory.
- SM2Signer.getZ(byte[]) is now protected rather than private, so a subclass can substitute or suppress the Z value - H(ENTL || ID || a || b || xG || yG || xA || yA), 5.1.4.4 of the draft RFC "SM2 Public Key Algorithms" - that the signer prepends to the message before e is calculated. Returning a zero-length array leaves the message unprefixed, so a signer constructed with a NullDigest signs and verifies a caller-supplied pre-hashed e exactly as it is passed in, which is what a remote signing service needs when Z and the message hash are computed on the client side. The signatures such a signer produces are the same ones the standard signer produces for the same message, and each verifies what the other signed; the default Z computation and every exception message are unchanged (github #2429).

### 2.2.4 Additional Notes

- The Rainbow implementation under org.bouncycastle.pqc.legacy.rainbow has been removed, together with its pqc.crypto.util key-factory entries and the "Rainbow" name in the BCPQC provider's algorithm list, which had had no Mappings class behind it for some time and so registered nothing. Rainbow was a NIST round-three finalist that was not selected for standardisation, following Beullens' 2022 key-recovery attack against its SL 1 parameter set; the JCE-side registrations, parameter spec and key classes were removed earlier. Keys carrying the BCObjectIdentifiers.rainbow\* object identifiers no longer decode, though the object identifiers themselves are retained, as is org.bouncycastle.math.raw.GF256AES, which is shared with UOV, MQOM and SDitH.
- The OpenSSH key vectors in the test sources carried the user and host name of whoever generated them in the key comment field - invisible in the source, but recoverable by anyone decoding the blob, and flagged as leaked credentials by secret scanners when the published source artifacts are ingested. All fifteen affected keys across OpenSSHKeyParsingTests and OpenSSHSpecTests have been regenerated with the comment "bc-test-vector", keeping each key's original type and size, and both classes now carry a header marking them as deliberately published test vectors. The keys were never used to protect anything and there is nothing to rotate; this removes the personal identifiers and gives anyone triaging a scanner alert something to find (github #2376).
- Two pieces of test material were being packaged into published artifacts by the Ant builds and no longer are. org.bouncycastle.openpgp.OpenPGPTestKeys, a test fixture holding armored key blocks as string constants, sits in the main-namespace openpgp package and is named Keys.java rather than Test.java, so it matched none of the bcpg copy's excludes and was compiled into bcprov's companion bcpg jar on both Ant lines - and into their sources and javadoc jars - from 1.81 onwards; it is now excluded there and added to bctest instead, where the openpgp.api tests that reference it resolve it from. Separately, the twenty PEM certificate fixtures under org/bouncycastle/est/test/san reached the bcpkix sources jars on both lines, because the existing test excludes there stop one directory below test/, and the javadoc copy independently pulled in the test package.html files. Neither artifact ever carried key material and the Gradle-built jdk18on artifacts were unaffected, but test certificates in a published source artifact are the sort of thing a secret scanner reports. The remaining test sources in the Ant sources and javadoc jars, which predate these and affect bcpg, bctls, bcutil and bcmail, are unchanged in this release.
- The Picnic implementation under org.bouncycastle.pqc.legacy.picnic has been removed, together with its BCPQC provider support - the KeyFactory / KeyPairGenerator / Signature registrations, PicnicParameterSpec, the PicnicKey interface and the pqc.crypto.util key-factory entries - along with the three LowMC matrix resources (about 1.2MB) the engine loaded. Picnic was a NIST round-three alternate candidate that was not selected for standardisation. Keys carrying the BCObjectIdentifiers.picnic\* object identifiers no longer decode through either provider, and the hardcoded Picnic branch in BouncyCastleProvider.getPublicKey - the only reason a Picnic public key resolved through the BC provider at all, since the converter table only ever held the picnic_key parent arc that no key names - is gone with it. The object identifiers are retained, as are the Picnic entries in the pkix algorithm-name and digest-finder tables, so an existing Picnic-signed artifact's metadata can still be named even though it can no longer be verified.
- The lightweight Hawk and CRYSTALS-Dilithium implementations have been relocated from org.bouncycastle.pqc.crypto.hawk and org.bouncycastle.pqc.crypto.crystals.dilithium to org.bouncycastle.pqc.legacy.hawk and org.bouncycastle.pqc.legacy.crystals.dilithium, joining the other legacy PQC families already under org.bouncycastle.pqc.legacy (bike, picnic, rainbow, sphincsplus). The classes themselves are unchanged; callers using them directly need to update their imports, and the JPMS exports move with them.
- BCPQC provider support for Hawk and CRYSTALS-Dilithium has been removed: the KeyFactory / KeyPairGenerator / Signature registrations, org.bouncycastle.pqc.jcajce.spec.HawkParameterSpec and DilithiumParameterSpec, and the two key interfaces. The BC provider also no longer registers key-info converters for the hawk256 / hawk512 / hawk1024 object identifiers, so those keys no longer decode through it either, and the unreferenced org.bouncycastle.jcajce.provider.asymmetric.Dilithium mappings class left behind in 1.85 has gone with them. The lightweight implementations remain available - see the relocation note below - and ML-DSA (org.bouncycastle.crypto.signers.mldsa, registered in the BC provider) is the standardised successor to Dilithium.
- As flagged in the 1.85 release notes, the deprecated FrodoKEM implementation under org.bouncycastle.pqc.crypto.frodo has been removed, together with its BCPQC provider support: the Frodo KeyFactory / KeyPairGenerator / KeyGenerator / Cipher registrations, org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec and org.bouncycastle.pqc.jcajce.interfaces.FrodoKey. Use the ISO/IEC 18033-2 FrodoKEM added in 1.85 under org.bouncycastle.crypto instead (crypto.kems.FrodoKEMGenerator / FrodoKEMExtractor and crypto.params.FrodoKEM\*), which is registered in the BC provider. Note that keys carrying the superseded BCObjectIdentifiers.frodokem\* object identifiers no longer decode through either provider, as the key-info converters for them are gone with the implementation.
- The deprecated NIST round 3 Classic McEliece implementation under org.bouncycastle.pqc.crypto.cmce has been removed, together with its BCPQC provider support: the KeyFactory / KeyPairGenerator / KeyGenerator and Cipher registrations, CMCEParameterSpec, the CMCEKey interface, the org.bouncycastle.pqc.asn1 CMCEPublicKey / CMCEPrivateKey structures and the pqc.crypto.util key-factory entries. Use the ISO/IEC 18033-2 Classic McEliece added in 1.85 under org.bouncycastle.crypto instead (crypto.kems.CMCEKEMGenerator / CMCEKEMExtractor and crypto.params.CMCEParameters), which is registered in the BC provider. Keys carrying the superseded round-3 BCObjectIdentifiers.mceliece\*\_r3 object identifiers no longer decode through either provider, and the non-standardised mceliece348864 size, which ISO never published, is gone with the round-3 implementation that carried it.
- The deprecated getPublicKey() / getPrivateKey() accessors on the ISO/IEC 18033-2 FrodoKEM and Classic McEliece key parameter classes - org.bouncycastle.crypto.params FrodoKEMPublicKeyParameters, FrodoKEMPrivateKeyParameters, CMCEPublicKeyParameters and CMCEPrivateKeyParameters - have been removed; use getEncoded(), which they duplicated.
- The deprecated XWingPrivateKeyParameters constructor taking org.bouncycastle.pqc.crypto.mlkem key parameters has been removed, as flagged when the ML-KEM classes were promoted to org.bouncycastle.crypto in 1.85; use the constructor taking org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters / MLKEMPublicKeyParameters instead. X-Wing itself is otherwise unchanged and no longer references the deprecated package.
- ML-DSA signature verification (org.bouncycastle.crypto.signers.MLDSASigner / HashMLDSASigner, and the corresponding JCA Signature.MLDSA\* / Signature.HashMLDSA\* algorithms) returns false uniformly for a cryptographically wrong signature and for one that is structurally malformed per FIPS 204 Algorithm 8 - wrong length, an out-of-order or duplicate hint index, or a hint weight exceeding the parameter set's omega - and never raises SignatureException for a decode failure. This differs from some other providers, including the JDK's own SUN ML-DSA implementation, which throws for a decode failure and reserves false for a well-formed-but-wrong signature, so code relying on Signature.verify() to tell "malformed" from "wrong" cannot do so against the BC provider. This is documented behaviour, not a defect (github #2367).
- org.bouncycastle.operator.jcajce.JcaContentSignerBuilder no longer creates new legacy generic composite (id_alg_composite) signatures: the constructor's CompositeAlgorithmSpec handling and the CompositePrivateKey short-circuit that drove it have been removed, and CompositeAlgorithmSpec is deprecated accordingly. Creating a modern fixed-algorithm Composite ML-DSA signature is unaffected. Verifying an existing legacy composite signature through JcaContentVerifierProviderBuilder still works in this release but is planned for removal in the next one, so callers still relying on the legacy format for verification should migrate to a modern fixed-algorithm composite key.
- As announced in the 1.85 release notes, the deprecated ML-DSA (FIPS 204) implementation under org.bouncycastle.pqc.crypto.mldsa has been removed. Use the standardised implementation under org.bouncycastle.crypto instead (crypto.params.MLDSA\* / crypto.generators.MLDSAKeyPairGenerator / crypto.signers.MLDSASigner and HashMLDSASigner), which is registered in the BC provider; org.bouncycastle.cert.plants.bc.BcMTCSigners, the only production caller still on the deprecated package, now uses it. The ML-DSA entries in the org.bouncycastle.pqc.crypto.util key factories have been removed rather than repointed, since org.bouncycastle.crypto.util covers the same object identifiers and is the path the JCE key classes take, so a caller decoding or encoding ML-DSA keys through pqc.crypto.util should now use the org.bouncycastle.crypto.util classes of the same names. No object identifiers are affected, and existing ML-DSA certificates and keys decode exactly as before.
- As announced in the 1.85 release notes, the deprecated ML-KEM (FIPS 203) implementation under org.bouncycastle.pqc.crypto.mlkem has been removed. Use the standardised implementation under org.bouncycastle.crypto instead (crypto.params.MLKEM\* / crypto.generators.MLKEMKeyPairGenerator / crypto.kems.MLKEMGenerator and MLKEMExtractor), which is registered in the BC provider. The ML-KEM entries in the org.bouncycastle.pqc.crypto.util key factories have been removed rather than repointed, since org.bouncycastle.crypto.util covers the same object identifiers and is the path the JCE key classes take, so a caller decoding or encoding ML-KEM keys through pqc.crypto.util should now use the org.bouncycastle.crypto.util classes of the same names. For the same reason PQCOtherInfoGenerator.PartyU/PartyV no longer have an ML-KEM branch and keep their org.bouncycastle.pqc.crypto.KEMParameters constructor parameter, NTRU being the one KEM left there; ML-KEM OtherInfo generation is covered by org.bouncycastle.crypto.util.OtherInfoGenerator. No object identifiers are affected, and existing ML-KEM certificates and keys decode exactly as before.
- As announced in the 1.85 release notes, the deprecated SLH-DSA (FIPS 205) implementation under org.bouncycastle.pqc.crypto.slhdsa has been removed. Use the standardised implementation under org.bouncycastle.crypto instead (crypto.params.SLHDSA\* / crypto.generators.SLHDSAKeyPairGenerator / crypto.signers.SLHDSASigner and HashSLHDSASigner), which is registered in the BC provider. The SLH-DSA entries in the org.bouncycastle.pqc.crypto.util key factories have been removed rather than repointed, since org.bouncycastle.crypto.util covers the same object identifiers and is the path the JCE key classes take, so a caller decoding or encoding SLH-DSA keys through pqc.crypto.util should now use the org.bouncycastle.crypto.util classes of the same names. No object identifiers are affected, and existing SLH-DSA certificates and keys decode exactly as before.
- BCJSSE: server-side OCSP stapling is configured by the same system properties as SunJSSE, and like SunJSSE they are read per SSLContext rather than once per class load, so one process can host a context that staples and a context that does not. jdk.tls.server.enableStatusRequestExtension (default false) enables it; jdk.tls.stapling.cacheSize (256), cacheLifetime (3600 seconds), responseTimeout (5000 milliseconds), responderURI, responderOverride (false) and ignoreExtensions configure it, with zero for either cache setting meaning no limit of that kind rather than no caching. The response timeout is the exception to that reading - it bounds a handshake thread, where "no limit" is not something to configure by accident - so its minimum is one millisecond and a zero is refused with a warning and the default used instead, as a negative or non-numeric value is for any of these properties. Two differences from SunJSSE are deliberate. First, jdk.tls.stapling.ignoreExtensions defaults to true here: the OCSP request extensions in question are the client's to choose and a nonce among them makes every response single-use, so honouring them would let a client force an outbound OCSP request per handshake, which is what the cache exists to prevent - setting the property to false restores parity, and what it then forwards is the nonce and only the nonce, a nonced request being answered outside the cache rather than served from it or put into it. Second, a response stating no nextUpdate is never cached, where SunJSSE holds one for cacheLifetime; this matches how the CertPath validator side of the library already reads RFC 6960 sec. 4.2.2.1. One further property is specific to this implementation: org.bouncycastle.jsse.server.stapling.failureLifetime (60 seconds) sets how long a failed lookup suppresses further attempts for the same certificate. Note also that fetches are made on the handshake thread within the responseTimeout budget rather than on a background thread pool as SunJSSE uses, so the first handshake needing a given response pays for retrieving it.
- Unreachable classes for RFC 3281 cert-path services have been removed.
- The MLS gRPC interop test harness has moved out of the published bcmls jar, where it was org.bouncycastle.mls.client, into the non-publishing misc module as org.bouncycastle.mls.examples.client, and its gRPC and protobuf dependencies are now taken by Maven coordinate at versions clear of CVE-2024-7246, CVE-2024-7254 and CVE-2025-55163.

### 2.2.5 Security Advisories.

Release 1.86 deals with the following CVEs:

- CVE-2026-17507 - MLS membership checks compare a uint32 leaf_index as signed, admitting an out-of-range sender.
- CVE-2026-17508 - Password-based KDF cost parameters honoured unbounded from untrusted input across the remaining PBE entry points.
- CVE-2026-18036 - NTRU leaks private key information by reducing secret values with a non-constant-time integer division.
- CVE-2026-18040 - HQC leaks private key information through secret-indexed GF(2^8) tables and a secret-dependent fixed-weight sampler.
- CVE-2026-71885 - MLS X.509 credential not bound to the LeafNode signature key.
- CVE-2026-71886 - OpenPGP certification accepted from a subkey without certification authority.
- CVE-2026-71887 - OpenPGP data signature accepted from a signing subkey without cross-certification.
- CVE-2026-71888 - CMS AuthenticatedData exposes attacker-inserted authAttrs when digestAlgorithm is absent.
- CVE-2026-71889 - PKIXCertPathReviewer does not apply X.509 name constraints to the target certificate.
- CVE-2026-71890 - MLS external commit can remove an arbitrary group member.
- CVE-2026-71891 - BLS12-381 key validation accepts a public key built on a foreign curve.
- CVE-2026-71892 - CMS key-transport recipient key-size validation never runs for RFC 9709 HKDF-derived keys.
- CVE-2026-85515 - OpenPGP message truncation not reported, bypassing the SEIPDv1 integrity check.

<a id="r1rv85v2"></a>

### 2.3.1 Version

Release: 1.85.2\
Date: 2026, 7th August.

### 2.3.2 Defects Fixed

- The AES-256/CBC Cipher registered against the id_aes256_CBC OID (org.bouncycastle.jcajce.provider.symmetric.AES\$CBC256) passed 192 rather than 256 as its key size, so a Cipher obtained via that OID and initialised with a password-based key (PKCS12Key, PBKDF1Key, PBKDF2Key or a plain PBEKey), rather than the dedicated PBEWITHSHAAND256BITAES-CBC-BC alias, silently derived only a 192 bit key - an unannounced downgrade to AES-192. Ordinary use with a raw SecretKeySpec was unaffected (github #2390).
- Constructing BouncyCastleProvider built the AlgorithmParameters.EC SupportedCurves attribute by calling ECNamedCurveTable.getParameterSpec for every registered curve and discarding the result, forcing every lazy curve holder in the table and making provider construction markedly slower than in earlier releases. The attribute is now built with a presence check that does not materialise the parameters (github #2382).
- KCCMBlockCipher (DSTU7624-128/256/512 CCM mode) returned the input length rather than 0 from getUpdateOutputSize(int), but like CCMBlockCipher/KGCMBlockCipher it buffers all input until doFinal and produces no output on an update. Through the JCA layer this made Cipher.update(input, inOff, inLen, output, outOff) reject a correctly sized output buffer with ShortBufferException when decrypting (github #2354).
- The PKIX CertPathBuilder matched candidate issuers by subject name only during its depth-first search, so a CertStore containing many self-issued certificates sharing one subject name and never chaining to a trust anchor could be explored as a large number of partial paths. The builder now bounds the nodes visited per build, configurable via org.bouncycastle.x509.max_cert_path_build_nodes (default 262144).
- BigIntegers value-exact range checks are open-coded again: BigInteger.intValueExact and friends are missing on Android below API level 33 (github #2369).
- SICBlockCipher.getPosition() propagated its borrow incorrectly for counter increments carrying across 0xFF IV bytes, and skip() moved to the wrong position for backward moves smaller than the current intra-block offset. The full-block-IV counter advance is now bounded at 2^64 blocks, the short-IV range check covers the previously unchecked processBlock path, and the skip/seekTo increment cascades are a constant-time counter addition - fixing the skip(Long.MIN_VALUE) unbounded spin and a near-Long.MAX_VALUE mid-block overflow.
- An unreachable or failing OCSP responder was reported as a plain CertPathValidatorException with the message "configuration error", which the revocation checker treats as a definite result, so a connection failure aborted path validation instead of allowing fallback to CRL checking. It is now a recoverable failure naming the responder (github #2372).
- Salsa20Engine.skip(Long.MIN_VALUE) silently moved nothing while returning as though it had, because negating the argument overflowed back to itself; the move is now split so it either lands exactly or raises the existing past-zero exception. The same applies to the ChaCha family sharing the engine.
- ReasonsMask.hasNewReasons was written as (\_reasons | mask ^ \_reasons) != 0, where ^ binds tighter than |, so it reported new reasons for almost any pair of masks rather than testing whether the candidate carried reasons the accumulated mask did not.
- The RFC 5280 sec. 6.3.3 CRL scope rules - the (b)(1) cRLIssuer check, the (b)(2) issuing distribution point checks, the (c) delta CRL consistency checks and the (d) reasons intersection - are now single-sourced in the new pure-ASN.1 org.bouncycastle.asn1.x509.PKIXCRLValidator, with the provider's RFC3280CertPathUtilities delegating to it; behaviour and exception messages are unchanged. The pkix module's copy of the checks is unchanged on this release.
- The PBKDF2 keyLength taken from a BCFKS keystore is now bounded before deriving, matching the iteration count caps beside it and stopping the keyLength \* 8 conversion overflowing into a NegativeArraySizeException.
- BMPString content was read by sizing a char[] from the declared length before any content had arrived, so a short crafted header could drive an allocation of up to 1GB and an OutOfMemoryError out of a parse API declaring IOException. It is now read through DefiniteLengthInputStream.toByteArray, which grows its buffer as bytes arrive.
- The HPKE context advanced its sequence number even when Seal/Open failed, so a rejected ciphertext desynchronised the receiving context from the sender; it now advances only on success per RFC 9180 sec. 5.2, and the section's message limit is enforced rather than wrapping the counter.
- Sorting the elements of a DER SET re-derived an element's encoding every time the insertion sort shifted it, costing O(N^2) encodings. Each element is now encoded once and the ordering uses a stable O(N log N) sort; the j2me tree keeps its insertion sort, memoised, since CLDC has no java.util.Arrays.
- X500Name.hashCode() threw a NullPointerException for a name containing an RDN decoded from an empty SET, which any peer can encode, and was marking the value calculated before computing it, so once a style had thrown every later call quietly returned 0.
- HSSSigner.init and LMSSigner.init assigned only the key for the mode being set, so a signer initialised for verification still held the private key from an earlier signing init and would sign with it. Both keys are now cleared on every init.
- XMSSSigner.init and XMSSMTSigner.init assigned only the key for the mode being set, and verifySignature carried no mode check, so a signer re-initialised for signing still verified against the public key left by an earlier verification init - and returned true rather than failing.
- The multi-release overlay copies of the EdEC provider SPIs had drifted from the base implementations: on JDK 11+ the XDH KeyAgreement ignored the UserKeyingMaterialSpec salt and the org.bouncycastle.emulate.oracle property, and on JDK 11+/15+ keys from third-party providers exposing only their encoding were rejected. The SPIs now exist once, in the base tree, with version-specific key construction and conversion in the multi-release XDHKeys and EdDSAKeys hook classes.
- KeyStore.getCertificateAlias on a PKCS12 keystore could return the alias of an unrelated certificate: the alias and certificate enumerations were paired positionally, but keys() enumerates a copy whose order can diverge from the live table's once enough entries are present (github #2384).
- The RFC 5280 sec. 4.1.2.4 check rejecting certificates whose issuer is an empty distinguished name had no opt-out, breaking parsing of the non-PKIX self-signed identity certificates used by the libp2p TLS profile. Setting org.bouncycastle.x509.allow_empty_issuer_cert to "true" now relaxes the certificate parse path; generation and X509CertificateReviewer stay strict (github #2387).

<a id="r1rv85"></a>

### 2.4.1 Version

Release: 1.85, 1.85.1\
Date: 2026, July 12th

### 2.4.2 Defects Fixed

- Release 1.85.1 generated for Java 5 to Java 8 and Java 4 to deal with a packaging issue that occured with the bcprov and bcutil jars - the Maven SBOMs for both have been uploaded as well.
- The streaming S/MIME writers SMIMEEnvelopedWriter.Builder and SMIMESignedWriter.Builder (org.bouncycastle.mime.smime) emitted a caller-supplied withHeader(name, value) verbatim, each terminated by CRLF, so a name or value carrying an embedded CRLF - the natural case when an application populates a header such as Subject from user input - was folded into the message as extra header lines and, with a trailing CRLFCRLF, a forged body: MIME header injection (CWE-93). withHeader now rejects a name or value containing CR or LF with an IllegalArgumentException; the internally generated headers and well-formed caller headers are unaffected (github #2348).
- A version 6 OnePassSignature packet (org.bouncycastle.bcpg.OnePassSignaturePacket) generated for emission defaulted to the Legacy OpenPGP packet format, so under the default ROUNDTRIP encoding a v6 OPS packet built via PGPSignatureGenerator was written with a Legacy header, breaking interoperability with strict RFC 9580 consumers - sec. 4.2 states the Legacy format "SHOULD NOT be used to generate new data". The v6 constructor now defaults to the new packet format, mirroring the v6 SignaturePacket constructor; the high-level OpenPGP message API already forced the new format, version 3 packets retain the Legacy default, and a Legacy header can still be forced through PacketFormat.LEGACY (github #2347).
- OpenPGPCertificate (org.bouncycastle.openpgp.api) derived a key's expiration from the most recent applicable self-signature or binding without verifying it, so anyone able to tamper with a transferable public key - a keyserver upload, a mail attachment, a MITM of a key fetch - could append a later-dated subkey binding advertising KeyExpirationTime = 0 and have getExpirationTime() report the key as non-expiring, overriding the owner's genuine expiry. Expiry is now taken only from the most recent self-signature or binding that is cryptographically valid. The legacy PGPPublicKey.getValidSeconds()/getValidDays() accessors remain unverified by design, that class having no handle on the issuing key; their javadoc now points callers making trust decisions at OpenPGPCertificate.
- The OpenPGP NotationData signature subpacket parser (org.bouncycastle.bcpg.sig.NotationData) miscounted its own header when bounds-checking the body: the header is 8 octets - four flag octets, a 2-octet name length and a 2-octet value length - but verifyData reserved only 4, so a subpacket declaring more name or value data than it carried slipped past the length guard and then overran with an ArrayIndexOutOfBoundsException when read during signature verification rather than being cleanly rejected at parse time. The guard now accounts for the full 8-octet header, matching the truncation checks on the neighbouring subpackets (issue #2346).
- The soft-fail hard limit in org.bouncycastle.pkix.jcajce.X509RevocationChecker (Builder.setSoftFailHardLimit) compared elapsed downtime against the limit with a strict "\<", so a failure occurring exactly at maxTime was still treated as soft, contrary to the javadoc. With maxTime = 0 the second failure only hard-failed once a full millisecond had elapsed since the first, so on a fast machine two revocation checks within the same millisecond both soft-passed. The comparison is now inclusive, so the limit fires at maxTime as documented.
- KMIPInputStream (org.bouncycastle.kmip.wire) built its XMLEventReader from a bare XMLInputFactory, so a KMIP XML message carrying a DOCTYPE was processed and external SYSTEM entities resolved during parsing - an XML External Entity exposure permitting local file disclosure via file:// URIs, outbound requests via http:// URIs, and information disclosure through parse error messages. The factory is now configured with SUPPORT_DTD = false and IS_SUPPORTING_EXTERNAL_ENTITIES = false before the reader is created; messages without a DOCTYPE parse exactly as before (github #2315).
- Reading a GnuPG keybox (org.bouncycastle.gpg.keybox.KeyBox / BcKeyBox / JcaKeyBox) stopped at the first EMPTY_BLOB, treating that free or deleted slot as end-of-file, so any key blobs following it were silently dropped - a keybox laid out as three OpenPGP blobs, an empty blob and a fourth OpenPGP blob returned only three where gnupg reads four. An empty blob is now skipped by advancing past its declared length and parsing continues, including for a header-only empty blob; only a malformed length that would move the read position backwards or beyond the buffer still terminates the read (issue #2343).
- The CMS SignerInfo decoder org.bouncycastle.asn1.cms.SignerInfo cast the version element directly to ASN1Integer and the trailing unsignedAttrs element directly to ASN1TaggedObject, so a malformed-but-parseable SignerInfo whose first element is not an INTEGER, or whose trailing element is not a [1] tagged object, leaked an unchecked ClassCastException instead of the documented IllegalArgumentException - escaping the throws-CMSException contract of code reaching the decode through getSignerInfos() / getCounterSignatures(). Both elements now decode via getInstance, matching org.bouncycastle.asn1.pkcs.SignerInfo (issue #2342).
- The CMS attribute decoder org.bouncycastle.asn1.cms.Attribute cast the first two elements of its SEQUENCE directly to ASN1ObjectIdentifier / ASN1Set, so an attribute whose type is not an OBJECT IDENTIFIER, or whose value is not a SET, leaked an unchecked ClassCastException instead of the documented IllegalArgumentException - escaping the throws-CMSException contract of SignerInformation.verify() / getSignedAttributes() when verifying a malformed-but-parseable signed message. Both elements now decode via getInstance; well-formed attributes are unaffected.
- Materializing a definite-length ASN.1 object through DefiniteLengthInputStream.toByteArray() allocated the full declared length up front, before reading any content. Where ASN1InputStream wraps a raw InputStream the per-object limit falls back to Runtime.maxMemory(), so a six-byte OCTET STRING header declaring a near-heap length with no body could drive an OutOfMemoryError before a single content byte was read (CWE-789). The buffer is now grown incrementally as bytes arrive, so the allocation a short input can force is bounded; a truncated stream still fails with the same "DEF length ... object truncated by ..." EOFException. Callers wrapping a raw stream should still set an explicit limit through the ASN1InputStream(InputStream, int) constructor or the org.bouncycastle.asn1.max_limit property - this removes the amplification, not the need for a bound.
- The SP 800-208 XMSS / XMSS^MT parameter sets could not be carried through a PKCS#8 PrivateKeyInfo: PrivateKeyInfoFactory always used the legacy PQCObjectIdentifiers.xmss form, whose XMSSKeyParams carries only the tree height and tree-digest OID and cannot express them. A SHAKE256 private key threw IllegalArgumentException ("unknown tree digest: SHAKE256-LEN"), and a SHA-256/192 key - which shares id-sha256 with the RFC 8391 n=32 set - encoded to the wrong OID and round-tripped to a different parameter set, while the matching public key already used the RFC 9802 form, so a keypair's halves carried different OIDs. Private keys for all standard sets now use the same RFC 9802 id-alg-xmss-hashsig / id-alg-xmssmt-hashsig form as the public key, so the halves share one OID and a key round-trips losslessly. Non-standard tree heights keep the legacy form, which is still read on decode (issue #2176).
- The X.509 value objects returned by CertificateFactory ("X.509", "BC") deferred X.500 name validation to their lazy getSubjectX500Principal() / getIssuerX500Principal() accessors, so a distinguished name that decodes under BC's lenient X500Name but is rejected by the stricter X500Principal constructor parsed cleanly at generateCertificate() / generateCRL() and then threw an unchecked IllegalArgumentException the first time the name was read. For a certificate this escaped CertPathValidator.validate() as an unchecked exception rather than the declared CertPathValidatorException, the issuer being read before signature verification, so an attacker-supplied leaf could trigger it. X509CertificateObject and X509CRLObject now validate the names in their constructor and reject a malformed one with a checked CertificateParsingException / CRLException, so the object is never constructed.
- During PKIX revocation checking against an indirect CRL, the three getCertStatus implementations in org.bouncycastle.jce.provider and org.bouncycastle.pkix.jcajce read the entry's certificateIssuer through X509CRLEntry.getCertificateIssuer(), whose own guard covers only the IOException from X500Name.getEncoded() and lets the IllegalArgumentException from the X500Principal constructor escape on a structurally-decodable-but-invalid name. A malformed certificateIssuer in a validly signed indirect CRL therefore leaked an unchecked exception rather than the declared AnnotatedException. All three now wrap the read and fail closed with AnnotatedException ("CRL entry certificate issuer could not be parsed.") rather than swallowing it to null, which would fail revocation open.
- The JCE parameter-set classes KyberParameterSpec, SABERParameterSpec, HQCParameterSpec and SnovaParameterSpec (org.bouncycastle.pqc.jcajce.spec) built their static fromName(String) map with keys that never matched what getName() returns, so fromName(spec.getName()) returned null for every parameter set - Kyber was keyed "kyber512" against the ML-KEM names, HQC "hqc128" against "hqc-128", Snova with upper-case names against a lower-cased lookup, and SABER had no static initializer at all. Because the BCPQC key classes implement getParameterSpec() as fromName(...), every such public and private key returned null and key.getParameterSpec().getName() raised a NullPointerException. Each map is now keyed by the lower-cased getName() value, Kyber and HQC retaining their legacy aliases, so the lookup round-trips for all parameter sets.
- Decrypting a CMS/S-MIME EnvelopedData or AuthEnvelopedData addressed to a password recipient ran PBKDF2 with the iteration count taken straight from the PBKDF2Params in the recipient's keyDerivationAlgorithm, with no upper bound. That count travels in the unauthenticated PasswordRecipientInfo (RFC 3211) and EnvelopedData has no integrity gate before content decryption, so an attacker-supplied message could specify a count up to Integer.MAX_VALUE and make a single decryption attempt spin for tens of minutes. Both derivation paths - org.bouncycastle.cms.bc.BcPasswordRecipient and org.bouncycastle.cms.jcajce.EnvelopedDataHelper - now bound the count by Properties.PBE_MAX_ITERATION_COUNT (default 10,000,000, the ceiling the PBES2 PKCS#8/PEM decrypt path already applies) and throw a CMSException before deriving the key when it is exceeded.
- The X.509 NameConstraints parser (org.bouncycastle.asn1.x509.NameConstraints / GeneralSubtree) did not reject structurally invalid empty sequences: an empty permittedSubtrees [0] or excludedSubtrees [1] was accepted even though RFC 5280 sec. 4.2.1.10 defines GeneralSubtrees as SEQUENCE SIZE (1..MAX), and an empty GeneralSubtree, missing its mandatory base GeneralName, parsed with an unchecked ArrayIndexOutOfBoundsException escaping the IllegalArgumentException-declared parse path. Both now reject the empty sequence with "sequence may not be empty", matching the other SEQUENCE SIZE (1..MAX) extension types.
- Five more X.509 extension value parsers defined as SEQUENCE SIZE (1..MAX) by RFC 5280 - CertificatePolicies (sec. 4.2.1.4), PolicyMappings (sec. 4.2.1.5), ExtendedKeyUsage (sec. 4.2.1.12), CRLDistPoint (sec. 4.2.1.13) and SubjectDirectoryAttributes (sec. 4.2.1.8) - accepted a structurally invalid empty SEQUENCE, yielding a degenerate empty extension rather than failing the parse. Each now rejects one with "sequence may not be empty" in its parse constructor, matching AuthorityInformationAccess and NameConstraints (issue #2331).
- The GPG S-expression parser (org.bouncycastle.gpg.SExpression, reached through SExprParser.parseSecretKey / PGPSecretKey.parseSecretKeyFromSExpr) allocated the buffer for a canonical string directly from the attacker-declared length before reading any data - a token such as "(67108864:)" declares a 64 MiB string from a handful of input bytes - and on a short stream the two-argument Streams.readFully silently left the buffer zero-padded rather than failing. The length is now read incrementally in bounded increments, so the allocation tracks the bytes the stream actually delivers and a truncated canonical string is rejected with an EOFException at the genuine end of input (github #2338).
- org.bouncycastle.openpgp.PGPObjectFactory.nextObject(), which is declared to throw only IOException, leaked an unchecked ClassCastException on a stream presenting a top-level SECRET_SUBKEY packet: tag 7 is not handled by the nextObject() switch, so it fell through to a default tail that blindly cast readPacket()'s result to UnknownPacket, while readPacket() decodes it into a typed SecretSubkeyPacket. The default tail now rejects any packet readPacket() decodes into a concrete type that the switch does not handle with an IOException ("unexpected packet in stream: ..."), covering this tag and any other typed one missing now or later; the genuine unknown-packet path is unchanged.
- The BC provider aliased the ARIA-CCM content-encryption OIDs (id-aria128-ccm/192/256, 1.2.410.200046.1.1.37/38/39) to the AES "CCM" Cipher rather than to ARIA-CCM, so a Cipher or AlgorithmParameters obtained by ARIA-CCM OID silently ran AES-CCM. The ARIA-CCM OIDs now resolve to the ARIA CCM Cipher and a dedicated ARIA-CCM AlgorithmParameters/AlgorithmParameterGenerator (the ARIA-GCM OID aliases were already correct). ARIA-CCM is thus now usable through the standard OID-addressed JCE path; the previously registered ARIA "ARIAGCM"/"ARIACCM" ciphers are unaffected.
- The RFC 3029 DVCS request builder DVCSRequestInformationBuilder, when seeded from an existing request through its DVCSRequestInformationBuilder(DVCSRequestInformation) constructor, silently dropped the requester ([0] GeneralNames) and extensions ([4] Extensions) fields, so build() re-emitted the request without the original requester identity or any extensions - unrecoverably for extensions, since setExtensions() throws on a seeded builder. This is exactly the seed-and-re-issue path RFC 3029 sec. 9.1 describes for a DVCS modifying a received request. The constructor now copies both fields, so rebuilding a parsed request is byte-for-byte faithful.
- BCJSSE's established session (ProvSSLSession) threw UnsupportedOperationException from getRequestedServerNames(); only the transient handshake session implemented it, so a server (e.g. Jetty) could not read the SNI the client requested once the handshake had completed. The requested server names are now captured from the handshake and retained on the established session, so getRequestedServerNames() returns them (an empty list when no SNI was sent, per the ExtendedSSLSession contract) on both the client and server side (issue #1773).
- BCJSSE endpoint identification for the HTTPS algorithm matched a dNSName SAN wildcard in any label of the certificate name rather than only in the complete left-most label, checkEndpointID dispatching the HTTPS case to HostnameUtil.checkHostname in the all-labels mode. A certificate whose SAN was "foo.\*.com" therefore matched "foo.evil.com", and "\*.\*.com" matched any two-label .com host - a weakening of the client's defence against an impersonating server, and more permissive than both SunJSSE and RFC 6125 sec. 6.4.3 / RFC 9525 sec. 6.3, which require the wildcard to be the complete content of the left-most label. The HTTPS path now matches left-most-label wildcards only, as the LDAP path already did; only a certificate carrying a wildcard in a non-left-most label, which no publicly-trusted CA will issue, changes outcome.
- A parameter-set-locked HQC KeyGenerator threw a NullPointerException when initialised with a KEMGenerateSpec or KEMExtractSpec, a consequence of the HQCParameterSpec fromName() mis-keying covered above; HQCKeyGeneratorSpi now compares against the upper-cased parameter name, matching the key's getAlgorithm(), as the other KEMs do. The dash form ("HQC-128") is now the primary registered algorithm name across KeyFactory, KeyPairGenerator, KeyGenerator, Cipher and KEM, matching getName() and the pre-existing KEM registrations, with the non-hyphenated names retained as aliases. The equivalent handling in the NTRU+ KEM KeyGenerator was aligned to the same pattern.
- The lightweight cert-path validation rule org.bouncycastle.cert.path.validations.CRLValidation selected a CRL from the supplied Store by matching the issuer DN only, then consulted its revoked list without ever verifying the CRL signature, so code populating the Store from an attacker-influenceable feed could be given a forged CRL bearing the CA's issuer DN - an empty list to suppress a real revocation, or a fabricated entry to deny a valid certificate - and trust it. Each matched CRL's signature is now verified against the issuing CA's public key first, mirroring ParentCertIssuedValidation: a new constructor takes the trust anchor's SubjectPublicKeyInfo and an X509ContentVerifierProviderBuilder, and the previous (X500Name, Store) constructor is deprecated and fails closed, as it cannot verify signatures. The full JCA path already verified CRL signatures.
- The default BC "BKS" keystore would silently load a legacy version 0/1 store. Those formats derive the HMAC integrity key at only the digest size in bits rather than bytes - a 16-bit key for the SHA-1 HMAC - which is brute-forceable offline, so an attacker able to supply or tamper with a keystore file could downgrade the unauthenticated on-disk version field, forge a valid integrity MAC over modified contents such as an injected trusted certificate, and have it accepted (CVE-2018-5382). Loading a version 0/1 store through the default "BKS" type now throws an IOException unless the caller opts in through Properties.BKS_ENABLE_V1 ("org.bouncycastle.bks.enable_v1"), which already gated creation of such stores and the separate "BKS-V1" type. The default type continues to read and write version 2 unchanged.
- The default BC "BKS" keystore and the legacy "BKS-V1" type derived the integrity-MAC key using the PBE iteration count read from the keystore header with no upper bound. KeyStore.load(stream, password) runs that derivation before the HMAC integrity check, so an attacker able to supply the file - the caller supplying the password being the normal load shape - could set the count near 2^31 and pin a CPU core for minutes per call, a pre-integrity-check denial of service; the store salt length was already bounded but the count was not. It is now rejected up front with an IOException when outside the new Properties.BKS_MAX_IT_COUNT (default 1048576), mirroring the caps on the UBER, PKCS12 and BCFKS stores, and the same bound applies to the per-entry count read when decrypting a sealed key. The BKS writer emits around 1024-2047.
- ArmoredInputStream mishandled dash-escaping in cleartext-signed messages. RFC 4880 sec. 7.1 requires every cleartext line beginning with a dash to be prefixed with "- ", but the reader instead dropped the two leading characters of any line starting with a dash, so a signature computed over "payload" also verified against a tampered "-Xpayload" line. A leading dash that is neither a "-----" armor header nor a "- " escape is now treated as malformed and rejected with an ArmoredInputException by default; RFC-conformant messages are unaffected, and ArmoredInputStream.Builder.setRejectPrefixedDashesInCSFMessages(false) restores a lenient mode that surfaces the offending bytes verbatim so the signature check fails rather than silently dropping them (github #2329).
- KGCMBlockCipher (DSTU 7624 GCM mode, and the KGMac built on it) did not detect nonce reuse: re-initialising the same instance for encryption with an identical key and nonce was silently accepted, though as with any GCM-family mode that leaks the authentication key and the XOR of the plaintexts. init now rejects it with an IllegalArgumentException ("cannot reuse nonce for KGCM encryption"), matching the existing GCMBlockCipher guard; reset()-based reuse, a fresh nonce, a fresh key and re-initialisation for decryption are all unaffected.
- KGCMBlockCipher (DSTU 7624 GCM mode) applied the AEADParameters initial associated text to its accumulator on init() without first clearing it, so re-initialising an instance carried the previous operation's associated data - left in the buffer by the prior doFinal's reset() - into the next authentication tag, producing a tag over the old AAD concatenated with the new and differing from a freshly constructed cipher. init() now resets the associated-text buffer in both the AEADParameters and ParametersWithIV branches, so a re-initialised cipher behaves exactly like a new one; reset()-based reuse was already correct (github PR #2349).
- The AEAD block-cipher modes EAXBlockCipher, CCMBlockCipher, OCBBlockCipher and KCCMBlockCipher did not detect nonce reuse on re-initialisation for encryption - the same footgun the KGCMBlockCipher guard above and the long-standing GCMBlockCipher and ChaCha20Poly1305 guards already reject - even though encrypting two messages under one key and nonce leaks the authentication key and the XOR of the plaintexts. RFC 5116 sec. 2.1 and RFC 7253 sec. 5.1 put that obligation on the caller, so this is a defensive guard turning a silent violation into a fail-fast error. Each mode's init now throws IllegalArgumentException when the new nonce equals the previous one under the same key, CCM and OCB additionally catching the null-key form; reset()-based reuse, a fresh nonce or key, and decryption are unaffected. GCMSIVBlockCipher and KXTSBlockCipher are deliberately not guarded.
- CCM (CCMBlockCipher) released unverified plaintext on a failed authentication check: decryption CTR-decrypted the whole payload straight into the caller-supplied output buffer and only then compared the MAC, so on a tag mismatch it threw InvalidCipherTextException but left the unverified plaintext in that buffer, never zeroed. A caller that exposes the buffer on the failure path - through pooled-buffer reuse, logging or memory inspection - could thereby use forged ciphertexts as an unauthenticated CTR decryption oracle, contrary to NIST SP 800-38C sec. 6.2. CCM is non-streaming, so decryption now produces the plaintext into a private buffer, verifies the MAC, and copies to the caller's output only on success, clearing the private buffer on failure, as GCMSIVBlockCipher already did.
- The DSTU 7624 (Kalyna) AEAD modes KCCMBlockCipher and KGCMBlockCipher released unverified plaintext on the same failure path as CCM above, writing the recovered plaintext into the caller's output buffer before the authentication tag was compared. KGCM authenticates the ciphertext, so it now verifies the tag before decrypting; KCCM authenticates the plaintext, so it decrypts into a private buffer and copies to the caller's output only once the MAC verifies, clearing the private buffer on failure. Output for valid ciphertexts is unchanged.
- KCCMBlockCipher (DSTU 7624 CCM mode) no longer appends the authentication tag to the recovered plaintext on decryption. It previously wrote plaintext || MAC into the caller's output buffer while reporting only the plaintext length, leaving the verified MAC past the returned length, and getOutputSize() returned len + macSize for decryption as well as encryption. Decryption now writes the plaintext alone - the MAC remains available through getMac() - and getOutputSize() returns len - macSize, matching the contract CCMBlockCipher, GCMBlockCipher and KGCMBlockCipher follow. The output-buffer length check was made mode-specific so a caller may pass a plaintext-sized buffer on decryption, and getOutputSize() now accounts for buffered data so the multi-part path is sized correctly. MAC verification itself is unchanged.
- BIKE KEM decapsulation hardened the Fujisaki-Okamoto implicit-rejection step. The BGFDecoder returned null on a decoding failure, which the decapsulation path then dereferenced, raising a NullPointerException before the implicit-rejection branch could run - both crashing on malformed ciphertext and acting as a decryption-failure oracle; the decoder now always returns the recovered error vector and the re-encryption check rejects a bad decode. Separately, the final select between the genuine seed and the rejection seed sigma was written as a data-dependent if/else on the constant-time comparison result, so the branch direction leaked the FO oracle bit; it is now a branchless constant-time move (Bytes.cmov), as FrodoEngine already used, defending against the Guo-Johansson-Nilsson (CRYPTO 2020) timing key-recovery attack. KAT vectors are byte-identical.
- Salsa20Engine, ChaChaEngine and ChaCha7539Engine detected the carry out of the low 32-bit counter word in advanceCounter(long) with a signed comparison where an unsigned one is required, so a skip() from a non-zero counter by a distance whose low word crosses the 0x80000000 boundary mis-set the high counter word: for Salsa20 and ChaCha this silently desynced the 64-bit block counter after a large random-access seek, and for the 32-bit ChaCha7539 counter it both threw "attempt to increase counter past 2^32" on a valid skip and could miss a genuine wrap. The carry is now computed unsigned, matching retreatCounter(long). Sequential encryption and seekTo() from reset were already correct, so all KAT vectors are byte-identical.
- The lazy ASN.1 SEQUENCE parse path (ASN1InputStream with lazyEvaluate=true, used by the CMS and X509CRLHolder stream parsers) did not enforce the nested-construction depth guard the eager path applies: a lazily parsed SEQUENCE captured its contents as raw bytes and LazyEncodedSequence.force() re-parsed them through a fresh ASN1InputStream, resetting the depth budget (org.bouncycastle.asn1.max_cons_depth, default 64) at every level. Any whole-tree operation on a crafted deeply nested blob therefore recursed without bound and could raise a StackOverflowError, a denial of service for a consumer parsing untrusted CRLs, CMS or certificates. The remaining budget is now threaded into LazyEncodedSequence and LazyConstructionEnumeration, raising the same "maximum nested construction level reached" ASN1Exception the eager path raises.
- The OER decoder (OERInputStream), which parses IEEE 1609.2 / ETSI TS 103 097 V2X structures before any signature verification, was hardened against three denial-of-service vectors reachable from a small crafted input. parse() recursed with no nesting-depth bound and the 1609.2 schema is cyclic, an Ieee1609Dot2Data nesting inside its own SignedData payload, so a few KB repeatedly selecting the signedData CHOICE drove a StackOverflowError; a hard depth cap, threaded across the open-type boundary, now rejects over-deep input. A SEQUENCE-OF decoded its element count from a few attacker-controlled bytes and looped that many times allocating objects without checking it against the remaining input, so a count such as 7F FF FF FF drove roughly 2^31 allocations; the count is now bounded by the bytes available, and the fixed-width element decoders fail on a short read rather than silently yielding 0 or TRUE. And the open-type EXTENSION branch allocated directly from an attacker-controlled length, bypassing the cap every other branch honours; it now goes through the same bounded helper.
- IETFUtils.valueToString - reached from X500Name.toString() / equals() / hashCode() and from X509Certificate.getSubjectX500Principal().toString() - escaped RFC 4514 special characters and leading or trailing spaces by inserting a backslash into the StringBuilder it was scanning. Because each insert shifts the remainder of the buffer, escaping a value of n special characters cost O(n^2) character moves, so a single large attacker-supplied RDN - a long PrintableString of commas in a certificate, CSR, CRL or CMS SignerIdentifier - could pin a CPU core when the X500Name was logged, compared, hashed or printed. The escaping now runs in a single linear pass into a fresh builder; the produced string is unchanged.
- The jdk1.4 build variant of LDAPStoreHelper (org.bouncycastle.x509.util, used by bcprov-jdk14) did not escape DN-derived values before concatenating them into an LDAP search filter, so the CVE-2023-33201 filter-injection fix never reached that distribution: the jdk14 Ant build overlays this file, which carries its own private parseDN, over the patched main-Java one. A certificate whose Subject or Issuer CN embedded LDAP filter metacharacters could therefore rewrite the DirContext.search() filter when certification-path building or CRL lookup invoked the helper. parseDN now applies the same RFC 2254 escaping as the other three variants; the Gradle-built jars were already fixed.
- Importing a Diffie-Hellman or DSA public key validated it by computing a modular exponentiation - and, for DH safe primes, a Legendre symbol - modulo the supplied prime p, with no bound on the size of p. A crafted SubjectPublicKeyInfo arriving through KeyFactory import or certificate parsing and carrying a multi-million-bit p therefore forced a very expensive computation at import time, an import-time CPU-exhaustion denial of service of the same class as CVE-2024-29857. DHPublicKeyParameters and DSAPublicKeyParameters now reject a modulus whose bit length exceeds a configurable bound before the exponentiation, mirroring the existing RSA cap; the bounds default to 16384 bits, well above any standardised group, and are controlled by the new Properties.DH_MAX_SIZE and Properties.DSA_MAX_SIZE.
- ArmoredOutputStream sanitized armor header values against the line feed only: the additive paths (addComment / setComment / setMessageId / setCharset) split values on \n and setVersion rejected \n, but neither handled a bare carriage return. A header value carrying an embedded CR - for example a parsed User-ID re-armored as a Comment through OpenPGPCertificate.toAsciiArmoredString() - therefore survived into a single physical header line, which a reader treating a lone CR as end-of-line, including BouncyCastle's own ArmoredInputStream, splits into a forged extra header or armor boundary. The split paths now split on CR, LF and CRLF, and the singleton path rejects CR as it rejects LF.
- The ArmoredOutputStream CR/LF hardening above covered only the Builder paths; the deprecated setHeader / addHeader methods and the ArmoredOutputStream(OutputStream, Hashtable) constructor still stored a header name or value verbatim, so an embedded CR or LF survived into a single physical header line and could inject an extra armor header or, through a blank line, terminate the header block early with the remainder parsed as base64 body. The rejection has been moved to the single sink every path funnels through, writeHeaderEntry, which now throws IllegalArgumentException("armor header must not contain CR/LF"), covering the deprecated setters, the Hashtable constructor and the Builder at once. The analogous PEM header writer org.bouncycastle.util.io.pem.PemWriter had the same gap and now rejects CR or LF the same way.
- OpenPGPMessageInputStream.OnePassSignatures.verify(), the inline one-pass-signature path of the high-level OpenPGP API, caught the PGPSignatureException thrown by OpenPGPSignature.sanitize() - which enforces the OpenPGPPolicy, rejecting weak hashes such as MD5 and SHA-1, unacceptable keys, unknown critical subpackets and pre-dated signatures - in a catch block whose body was an empty "// continue" comment with no statement, so execution fell through to the cryptographic verify() and the signature was added to the results as tested correct. A one-pass signature failing policy was therefore reported as valid through getSignatures() / isTestedCorrect(). The catch now reports the exception through the processor and skips the signature, matching the detached- and prefixed-signature paths.
- OpenPGP SEIPD v1 decryption from a public-key (PKESK) or other already-recovered session key still performed the legacy CFB "quick check" on the two repeated prefix bytes and threw PGPDataValidationException("data check failed.") before the MDC was verified. PGPPublicKeyEncryptedData has long suppressed this check to avoid the Mister-Zuccherato adaptive-chosen-ciphertext oracle, but PGPSessionKeyEncryptedData - reached by the high-level API after unwrapping a PKESK session key - did not, re-exposing a distinguishable early failure usable to recover plaintext. The quick check is now suppressed on that path, the SEIPD v1 MDC being the integrity check there; it is retained on the password-based path, where its failure and stream reset are what let the decryptor detect a wrong passphrase and try the next SKESK packet.
- Loading a BCFKS keystore (BcFKSKeyStoreSpi) derived the integrity-MAC key from the scrypt or PBKDF2 cost parameters carried in the keystore *before* verifying that MAC, with no bound on them. A crafted .bcfks declaring a scrypt cost of N=2^28 (about 68 GiB of working memory) or a PBKDF2 iteration count near 2^31 therefore forced unbounded memory or CPU consumption at load time, before any password or integrity check - a pre-authentication denial of service - where the PKCS#12 keystore already capped its iteration counts. The derivation now rejects a scrypt working-memory estimate above Properties.BCFKS_MAX_SCRYPT_MEMORY (default 1 GiB) or an oversized block size, and a PBKDF2 count above Properties.BCFKS_MAX_IT_COUNT (default 5,000,000), before running the KDF. The BCFKS writer's own parameters are well within the defaults.
- Decrypting a PBES2-protected PKCS#8 / PEM private key (JcePKCSPBEInputDecryptorProviderBuilder and JceOpenSSLPKCS8DecryptorProviderBuilder) derived the key from the scrypt or PBKDF2 cost parameters carried in the encrypted-key container with no bound. The container is not integrity-protected, so importing an attacker-supplied encrypted key - a routine operation - could be driven into multi-gigabyte scrypt memory or billions of PBKDF2 iterations. Both builders now reject a scrypt working-memory estimate above Properties.PBE_MAX_SCRYPT_MEMORY (default 1 GiB) or an oversized block size, and a PBKDF2 count above Properties.PBE_MAX_ITERATION_COUNT (default 10,000,000), before running the KDF; the defaults are generous enough for deliberately strong settings and are configurable.
- Completing the cost-parameter bounding above, the legacy PKCS#5 v1.5 PBES1 branch of those same two builders still fed the PBKDF1 iteration count carried in the encrypted-key AlgorithmIdentifier straight into key derivation with no bound. That parameter is unauthenticated and reachable through the routine PKCS8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo import path, so a crafted key declaring a count near 2^31 drove a long PBKDF1 hash loop. Both PBES1 branches now reject a count above Properties.PBE_MAX_ITERATION_COUNT (default 10,000,000) before deriving the key, matching the PBES2 branch in the same builders; legitimate PBES1 counts are far smaller.
- The RFC 4211 PKMAC / CMP password-based-MAC builder (PKMACBuilder) ran its iterated hash for the iteration count carried in the unauthenticated PBMParameter with no upper bound unless the caller had constructed the builder with an explicit maxIterations ceiling. Verifying a passwordBasedMac-protected CMP message feeds the incoming count straight into that loop, so an attacker-supplied message declaring a count near 2^31 could drive the recipient into billions of hash iterations. PKMACBuilder now applies a default ceiling (Properties.PKMAC_MAX_ITERATION_COUNT, default 10,000,000) when no explicit maxIterations was supplied, rejecting an oversized count with an IllegalArgumentException before the loop runs; an explicit maxIterations still takes precedence.
- The EST client (DefaultESTClient) followed an HTTP 3xx redirect whose Location pointed to any host, rebuilding the request - including its headers, so any Authorization credential, and its body, so the enrolment CSR - against the redirect target. A malicious or compromised EST server could therefore redirect an authenticated request to an attacker-chosen origin and have the client replay those credentials and the CSR there. redirectURL now follows only same-origin redirects, matching scheme, host and port, and refuses a cross-origin one with an ESTException; relative-Location redirects, which reuse the original origin by construction, are unaffected.
- DTLS handshake reassembly (DTLSReliableHandshake) sized each reassembly buffer from the full-message length declared in a fragment header - a uint24, up to about 16 MiB - with no bound, and created one reassembler per message_seq across the receive-ahead window, all at epoch 0 before any signature or Finished verification. A handful of small datagrams carrying minimal fragments with large declared lengths could therefore commit hundreds of MiB of attacker-controlled heap per peer, a pre-authentication denial of service. The non-DTLS path already rejected handshake messages exceeding the peer's getMaxHandshakeMessageSize(); the reassembler now applies the same bound before allocating, ignoring an over-sized fragment as it already ignores a malformed one.
- The JCE private-key classes BCMLDSAPrivateKey (ML-DSA), BCMLKEMPrivateKey (ML-KEM) and BCSLHDSAPrivateKey (SLH-DSA) compared their secret-bearing encodings in equals() with the variable-time Arrays.areEqual, whereas the secret-bearing private-key path should use the constant-time comparison (as the other BC private-key classes do). The comparison now uses Arrays.constantTimeAreEqual; the boolean result is unchanged.
- NTRU+ KEM decapsulation (NTRUPlusEngine) computed its re-encryption equality check in a constant-time loop but then converted the accumulated difference to the fail flag with a data-dependent branch, despite the method's "constant time" contract and the branchless form documented in its own comment. Because the fail flag drives a constant-time cmov of the shared secret, the branch reintroduced a Fujisaki-Okamoto decryption-failure timing oracle. The conversion is now branchless ((-acc) \>\>\> 31); the returned value, and so the KEM output, is unchanged.
- NTRU LPRime KEM decapsulation (NTRULPRimeKEMExtractor) recomputed the re-encrypted ciphertext components encBnew and encTnew but then assembled the candidate ciphertext for the Fujisaki-Okamoto check from the input ciphertext's own encB / encT bytes, discarding them. The constant-time comparison therefore compared the B and T components against themselves and only meaningfully checked the hc confirmation hash, so the implicit-rejection step never verified that the recovered message actually re-encrypts to the supplied ciphertext - and since the rounded B/T encoding is malleable, that weakened the IND-CCA2 guarantee the FO transform provides. The check now rebuilds the candidate ciphertext from the re-encrypted components, matching the encapsulator and the Streamlined NTRU Prime extractor; KAT vectors are byte-identical.
- Several post-quantum KEM decapsulators did not validate the length of the supplied encapsulation before decoding it, so a malformed or truncated ciphertext from the wire crashed decapsulation with an uncaught ArrayIndexOutOfBoundsException or NegativeArraySizeException - or, for Frodo, NTRU LPRime and Streamlined NTRU Prime, a ciphertext one byte short was silently accepted and decapsulated to a wrong shared secret - instead of being cleanly rejected. The SABER, Frodo (legacy round 3), Classic McEliece, HQC, NTRU+, NTRU LPRime, SNTRU Prime and legacy BIKE extractors now reject an encapsulation of the wrong length with an IllegalArgumentException ("encapsulation wrong length") before any decoding, matching the guard MLKEMExtractor and the standardised org.bouncycastle.crypto.kems extractors already had. KAT vectors are byte-identical.
- The NTRU+ KEM JCE wiring in the BCPQC provider was only partially functional. NTRUPlusParameterSpec.fromName() keyed its map on strings getName() never produces, duplicated the 864 entry and omitted ntruplus_1152, so it returned null for every parameter set: both key classes' getParameterSpec() returned null and a parameter-locked KeyGenerator raised a NullPointerException from engineInit; the map is now keyed by the lower-cased canonical name and includes all three sets. The per-parameter-set KeyGenerator and Cipher aliases also registered class names that did not match the actual classes, so getInstance for the three hyphenated names failed with a NoClassDefFoundError; the registrations now name the real classes. Finally two parameter-set mix-ups were corrected: the 768 Cipher SPI and the 1152 KeyPairGenerator SPI were both constructed with the 864 parameters, so one rejected genuine 768 keys and the other generated 864-sized ones. The lightweight API and key encodings are unchanged.
- The RFC 9579 PBMAC1 PKCS#12 keystore SPI (PKCS12PBMAC1KeyStoreSpi) read the outer authSafe ContentInfo's content with ASN1OctetString.getInstance(info.getContent()).getOctets(). A crafted PKCS#12 whose ContentInfo omits the OPTIONAL [0] EXPLICIT content field - and which carries no MacData, so the MAC block that would otherwise touch the content is skipped - left that null and the getOctets() raised a NullPointerException during engineLoad, a parse-time denial of service triggerable before any MAC or password check. The legacy PKCS12KeyStoreSpi already routes the same access through PKCS12Util.getContentOctets, which raises a diagnosable ASN1ParsingException, so the CVE-2024-0727 hardening was incomplete across the SPI pair; the PBMAC1 SPI now uses the same helper. The PKCS12PBMAC1StoreTest suite, previously not referenced by the package AllTests, is now wired in.
- PKIX certification-path validation built the RFC 5280 valid-policy-tree with no bound on its size. Policy mapping combined with the anyPolicy expansion (sec. 6.1.3 (d)(2) / 6.1.4) makes the tree grow multiplicatively per certificate, so a crafted chain that still chains to a trusted anchor - an attacker-controlled sub-CA, or an mTLS client-supplied chain - carrying policies and policy mappings at every level could drive the validator into exponential memory and CPU consumption, of the class of CVE-2023-0464; unlike OpenSSL, whose policy processing is off by default, BC builds the tree unconditionally. Validation now aborts with a CertPathValidatorException once the live node count exceeds Properties.X509_MAX_POLICY_NODES (default 8192, far above any legitimate tree), applied to every copy of the logic - the provider's validator and builder and both PKIXCertPathReviewer copies.
- X.509 name-constraint enforcement (PKIXNameConstraintValidator) was tightened against two bypasses by which a compromised or mis-issuing name-constrained intermediate CA could escape its constraints. directoryName matching searched for the constraint's first RDN at an arbitrary offset in the subject and matched the remaining RDNs from there, so a subject such as C=FR,O=Attacker,C=US,O=TrustedOrg,CN=victim was accepted under a permittedSubtree of C=US,O=TrustedOrg, where RFC 5280 sec. 4.2.1.10 / 7.1 require the constraint to be an initial prefix; matching now starts at the first RDN only, the relaxed GSMA SGP.22 anywhere-match staying available behind a property. And rfc822Name and URI host comparisons used an exact case-insensitive compare while the dNSName path strips an RFC 1034 trailing dot, so an excluded subtree could be evaded with one; those forms now apply the same canonicalisation.
- X.509 name-constraint enforcement was tightened against a further rfc822Name bypass of the same class as the trailing-dot issue above. Matching a certificate's rfc822Name against an email constraint derived the mailbox host by splitting at the first '@', but RFC 5321 sec. 4.1.2 allows a quoted local part to contain '@', so the domain is the text after the last one: a name such as "victim@evil.example"@bank.com is a mailbox in bank.com, yet the first-'@' split yielded a different host and slipped past an excluded subtree of bank.com. Because a quoted local part cannot be split unambiguously by simple slicing, a tested rfc822Name containing more than one '@' is now rejected when rfc822Name constraints are in force. That is deliberately stricter than RFC 5321, so the new Properties.X509_ALLOW_LENIENT_RFC822_NAME restores the previous parsing; it defaults to off, and ordinary single-'@' addresses are unaffected.
- CMS AuthenticatedData verification did not bind the content to the MAC when authenticated attributes were present. With authAttrs, RFC 5652 sec. 9.3 computes the MAC over DER(authAttrs), which carries a messageDigest attribute, so content integrity depends on the recipient additionally comparing that attribute against the digest over the content - and while RecipientInformation exposed the computed digest, it never performed the comparison, the documented verification pattern checking only the two MACs. Since AuthenticatedData authenticates but does not encrypt, an attacker could replace eContent with arbitrary bytes, leave authAttrs and the mac untouched, and the MAC comparison still succeeded. getMac() now verifies the recovered content digest against the messageDigest attribute and throws a CMSRuntimeException on mismatch, on both the in-memory and streaming paths, and getContentDigest() is now idempotent. Messages without authenticated attributes are unaffected.
- CMSSignedData.verifySignatures(...) returned true for a SignedData carrying no SignerInfos: RFC 5652 permits a degenerate certs-only SignedData with an empty signerInfos SET, and the verification loop simply falls through to "return true" when there are no signers, so an application using verifySignatures() as its top-level authenticity check would accept arbitrary attacker-supplied content wrapped in a zero-signer envelope. It now throws a CMSException ("no signers present in SignedData") when the signer set is empty. Counter-signature verification is unaffected - a signer with no counter-signatures remains valid - and applications expecting a certs-only structure should use getCertificates().
- BcRSAAsymmetricKeyUnwrapper, the lightweight CMS / PKIX RSA PKCS#1 v1.5 key-transport unwrapper, now carries a class-level javadoc note documenting that PKCS#1 v1.5 RSA decryption is subject to Bleichenbacher / Marvin adaptive chosen-ciphertext attacks: the unwrapper signals a padding failure by throwing rather than returning a random key of the expected length, so a service that decrypts attacker-supplied blobs with a static RSA private key and exposes the outcome - a distinguishable error, or a response-time difference - can act as a padding oracle. BC deliberately leaves the constant-time random-fallback mitigation to the protocol layer, as the TLS stack wires it for the RSA key exchange, and the javadoc now points callers exposing an online decryption oracle at RSA-KEM or RSA-OAEP instead. Documentation only.
- The composite (draft-ietf-lamps-pq-composite-kem / -sig) KEM and signature parsers split attacker-controlled key and signature bytes at fixed component offsets without first checking the input was long enough, so a crafted composite public key, private key or signature with a truncated body raised an uncaught NegativeArraySizeException, ArrayIndexOutOfBoundsException or IllegalArgumentException out of KeyFactory.generatePublic / generatePrivate - reachable through BouncyCastleProvider.getPublicKey when parsing a certificate or PKCS#8 - and out of Signature.verify, escaping those methods' declared contracts. compositekem.KeyFactorySpi, compositesignatures.SignatureSpi.engineVerify and CompositeMLKEMEngine decapsulation now bound-check the input length first and reject a too-short body with a diagnosable IOException or SignatureException.
- Three further secret-comparison sites were switched from the variable-time Arrays.areEqual to the constant-time Arrays.constantTimeAreEqual, matching the convention for secret-bearing comparisons: the DSTU 7624 (Kalyna) key-unwrap integrity check in DSTU7624WrapEngine, the only wrap engine still using the variable-time compare, and the legacy stateful-hash PQC private-key equals() implementations in BCXMSSPrivateKey, BCXMSSMTPrivateKey and BCSphincs256PrivateKey, the un-migrated siblings of the ML-DSA / ML-KEM / SLH-DSA keys hardened earlier in this release. The results are unchanged.
- The remaining secret-bearing private-key equals() implementations were likewise switched to the constant-time Arrays.constantTimeAreEqual, completing the migration begun earlier in this release. On the lightweight side LMSPrivateKeyParameters now compares its RFC 8554 master secret, the seed from which every LM-OTS private key is derived, in constant time, and HSSPrivateKeyParameters inherits the change through its component keys. On the JCE side the twenty BCPQC private-key wrappers - LMS, Dilithium, Kyber, Falcon, the four NTRU variants, SABER, Frodo, BIKE, Classic McEliece, HQC, SPHINCS+, Picnic, MAYO, MQOM, SDitH, SNOVA and NewHope - each compared their secret-bearing encoding with the variable-time form and now use the constant-time one; NewHope's secret is a short[], for which there is no constant-time primitive, so it compares its PKCS#8 encoding instead. The public LMS I identifier comparison is deliberately left variable-time.
- The classic JCA private-key classes likewise had their secret-scalar equals() comparisons made constant-time, matching the earlier EC / EdDSA / XDH hardening: BCRSAPrivateKey and BCRSAPrivateCrtKey (the private exponent, and for the CRT key p, q, both CRT exponents and the coefficient), BCDSAPrivateKey, BCDHPrivateKey, BCElGamalPrivateKey and BCGOST3410PrivateKey (the secret value x), and the DSTU 4145 and two ECGOST classes (the EC scalar d) now compare the secret BigInteger through the new BigIntegers.constantTimeAreEqual helper instead of BigInteger.equals; the public components and domain parameters keep the ordinary comparison. Separately, the HSS private-key regeneration path compared a freshly derived child seed against the stored master secret with Arrays.areEqual and now uses the constant-time form.
- X509CertificateHolder and X509CRLHolder, when constructed from a byte[] or InputStream, caught only ClassCastException and IllegalArgumentException from the ASN.1 decode and wrapped them in a CertIOException; other RuntimeExceptions thrown on malformed input - ASN1ParsingException and IllegalStateException from the lazy-sequence and tagged-object decoders, and a NullPointerException reachable in the certificate path - escaped a constructor declaring only IOException, so a caller catching IOException on untrusted input could still receive an uncaught RuntimeException. Both parse helpers now treat any RuntimeException from the decode as malformed input and wrap it in a CertIOException carrying the same "malformed data: ..." message; 80,000 mutated CRL and certificate inputs all surfaced as IOException.
- PKCS12KeyStoreSpi.engineLoad and its RFC 9579 PBMAC1 SPI pair parsed the untrusted PKCS#12 safe contents - AuthenticatedSafe / SafeBag / CertBag decode, ASN1OctetString.getInstance, embedded certificate generation - without catching the RuntimeExceptions those ASN.1 operations throw on malformed input, so a crafted .p12 could surface an uncaught IllegalArgumentException or a bare RuntimeException out of KeyStore.load, escaping the method's declared IOException contract - the same class as the X509CertificateHolder fix above. The safe-contents processing in both SPIs is now wrapped so any RuntimeException from the decode is re-thrown through Exceptions.ioException as an IOException.
- BCPBEKey.destroy() - the JCE PBEKey returned by the BC SecretKeyFactory PBE, PBKDF2 and scrypt key factories - zeroized the password and salt but left the derived key bytes, the actual secret, in memory: the derived key is held in the CipherParameters param field, as a KeyParameter or one wrapped in ParametersWithIV, and was never cleared, so a heap dump taken after a caller had dutifully called destroy() still contained it. destroy() now also overwrites the derived key held in param, recursing through ParametersWithIV to reach the wrapped KeyParameter; behaviour before destroy() and the post-destroy IllegalStateException are unchanged.
- Three provider and cache data races were closed. BouncyCastleProvider.getKeyInfoConverter and its PQC counterpart read the shared static keyInfoConverters HashMap with no synchronization while addKeyInfoConverter and getAsymmetricKeyInfoConverter both hold the map's monitor, so a read racing an add - a second provider construction re-running the registration, concurrent with a key decode on another thread - could observe a partially rehashed table and return a wrong or null converter; both reads now take the same monitor. Separately, OcspCache.getOcspResponse mutated its per-responder inner HashMap with no synchronization, so two threads validating certificates from the same responder could structurally corrupt it; the method is now static synchronized, matching CrlCache.getCrl.
- MLS (RFC 9420) external-proposal verification (Group.verifyExternal) looked up the sender's signature key from the group's external_senders extension with no null-check on the extension and no bounds-check on the wire-controlled sender_index, before verifying the signature. A PublicMessage carrying an EXTERNAL sender therefore crashed message processing with an uncaught NullPointerException, where the group has no such extension, or IndexOutOfBoundsException, where the index is out of range - a pre-verification denial of service on untrusted input. verifyExternal now rejects both with a diagnosable Exception before the lookup, matching verifyInternal's "Signature from blank node" rejection.
- MLS (RFC 9420) external-join verification (Group.verifyNewMemberCommit and verifyNewMemberProposal) dereferenced optional, wire-controlled message fields with no guard, the missed siblings of the verifyExternal fix above: Group.handle dispatches signature verification on sender type before any content-type or path validation, and the membership tag is not checked for these sender types, so a PublicMessage carrying either reached these methods on untrusted input. A Commit whose updatePath is absent - a legal decode - crashed verifyNewMemberCommit with a NullPointerException, and a NewMemberProposal carrying any non-Add proposal crashed verifyNewMemberProposal: a pre-verification, remote, unauthenticated denial of service. Both now reject the malformed message with a diagnosable Exception ("malformed NewMemberCommit" / "malformed NewMemberProposal") before the dereference.
- MLS (RFC 9420) message-key derivation (GroupKeySet.HashRatchet.get) advanced the per-sender hash ratchet by one HKDF step for every generation between its current position and the generation requested by an incoming message, with no bound on the gap. The generation is carried in the authenticated, sender-supplied message, so a group member could request one up to about 2^31 and force every recipient into billions of key derivations - an insider-reachable CPU-exhaustion denial of service, the generation sitting inside the AEAD-protected sender data. get now rejects a forward gap exceeding HashRatchet.MAX_FORWARD_RATCHET_STEPS (65536) with an InvalidParameterException before advancing, matching the existing expired-key rejection; legitimate gaps from reordering or loss within an epoch are far smaller.
- MLS (RFC 9420) PrivateMessage.protect left the per-message reuse_guard - the four bytes XORed into the AEAD nonce to guard against nonce reuse, RFC 9420 sec. 6.3.1 - all-zero on the send path, never randomizing it. With a constant guard the nonce for a given key and generation is fixed, removing the defence in depth the guard exists to provide, and two protections of the same content under the same key state produced byte-identical ciphertext. protect now fills reuse_guard from a SecureRandom per message, as the spec requires; the guard travels in the encrypted sender data and is applied by the receiver, so interop and decryption are unaffected.
- SExprParser.parseSecretKey() now auto-detects the GnuPG "Extended Private Key Format" - a set of "Name: value" header lines followed by the key S-expression under a "Key:" field - which has been the gpg-agent default since 2.2.20. This entry point previously assumed a bare canonical S-expression and failed on the leading header character ("unknown character encountered" for the on-disk private-keys-v1.d files modern GnuPG writes); it now routes an extended-format stream through PGPSecretKeyParser / OpenedPGPKeyData, leaving the canonical-format path unchanged (issue #794).
- The BC provider's BKS and UBER keystores (BcKeyStoreSpi) read length-prefixed certificate-chain, key, secret, sealed and salt fields from the stream and allocated arrays of the declared size before reading the data, with no upper bound, so a crafted keystore of a few dozen bytes declaring an Integer.MAX_VALUE length could drive an immediate OutOfMemoryError on KeyStore.load() regardless of heap size - and, loadStore() running ahead of the integrity-MAC comparison, regardless of the password supplied. The certificate chain is now decoded incrementally rather than pre-allocated from the declared count, and every length-prefixed block is read through a fixed 2 MiB buffer, a larger declared length being accumulated incrementally, so a stream not carrying the declared bytes fails with an EOFException after a bounded allocation. Store-header salt lengths are bounds-checked before allocation.
- LMS / HSS public key parsing (LMSPublicKeyParameters.getInstance / HSSPublicKeyParameters.getInstance, and so X.509 SubjectPublicKeyInfo decoding for id-alg-hss-lms-hashsig keys) now enforces the RFC 8554 well-formedness rules on untrusted encodings: an unknown LMS typecode is rejected with an IOException rather than surfacing as a NullPointerException, an unknown LM-OTS typecode is rejected rather than silently producing a key with null OTS parameters that would only fail later at verification, the HSS level count L must lie in 1..8 (sec. 6, which the key generation side already enforced), and an encoding carrying trailing data after the key is rejected, sec. 5.3 requiring exactly 24 + m bytes. The stream-based entry points used for keys embedded in HSS signature chains are unchanged apart from the typecode checks.
- RSADigestSigner.verifySignature, when accepting the legacy DigestInfo encoding that omits the RFC 8017 sec. 9.2-required NULL AlgorithmIdentifier parameter, compared the recovered DigestInfo against the expected one with a loop that ran only digest-length times over the trailing region. That region begins at the OCTET STRING tag two bytes ahead of the hash, so the loop stopped two bytes short and never compared the final two bytes of the message hash: a signature matching in its header and in all but the last two hash bytes was accepted as valid, weakening PKCS#1 v1.5 verification and widening the search space for a Bleichenbacher-style low-exponent forgery. The comparison now covers the entire trailing OCTET STRING - tag, length and every hash byte. The strict NULL-present path, the common case, was never affected.
- BCJSSE per-connection server logging (ProvTlsServer) and property-discovery logging (PropertyUtils) were emitted at INFO; they have been moved to FINE to match the level ProvTlsClient already used for the equivalent events (issues #2235 / #1705).
- KGCMBlockCipher (DSTU 7624 GCM mode), and so the KGMac built on it, authenticated a trailing partial block of associated data or payload by reading a full block out of the backing buffer; the bytes past the message length are not zeroed by reset(), so the GF(2^n) MAC depended on what the instance had previously processed and a partial-block MAC was non-deterministic across reuse. The trailing partial block is now explicitly zero-padded, matching the generic GCM/GMAC construction - the true bit length being bound by the trailing lambda field - which makes the result deterministic. Block-aligned input and the first use of a fresh instance are unaffected (issue #287).
- KCCMBlockCipher (DSTU 7624 CCM mode) advanced its gamma counter keystream with an independent per-byte add that dropped the carry between bytes; since the counter has only its lowest byte set to 1, only the low byte ever changed, so the keystream block repeated every 256 blocks and any message longer than 255 blocks was encrypted with a repeating keystream - a two-time pad, allowing recovery of XORed plaintext-block pairs from the ciphertext alone. The counter advance now propagates the carry across the whole block, matching the generic CCM counter and the sibling KCTR and KGCM modes. The published DSTU 7624 KAT vectors are short enough that their keystream never wrapped, so only messages exceeding 255 blocks change. This is the same defect class as CVE-2025-14813 (GOST CTR) (issue #287).
- UserAttributeSubpacketInputStream allocated the subpacket body buffer directly from the wire length header, guarded only by StreamUtil.findLimit(). For the BCPGInputStream used during packet parsing findLimit() returns close to the JVM heap size rather than the bytes actually available, so the guard was ineffective and a crafted User Attribute subpacket header declaring about 2 GiB forced a multi-gigabyte allocation before any body byte was read - a pre-authentication memory-exhaustion denial of service against any consumer importing untrusted OpenPGP certificates, and the sibling of CVE-2026-3505. The reader now rejects a body length above an absolute 2 MiB cap, matching SignaturePacket.MAX_SUBPACKET_LEN and PublicKeyPacket.MAX_LEN, independently of the findLimit() hint and before allocating.
- The MLS API compared received membership and confirmation tags against the locally computed HMAC values using early-exit array comparisons, giving a byte-by-byte timing oracle on secret-keyed MACs. The three verification sites (PublicMessage.unprotect, the Group external-join constructor and Group commit handling) now use Arrays.constantTimeAreEqual, and as defense-in-depth the secret-bearing equals() implementations on the MLS Secret and KeyGeneration classes now also compare their key material in constant time (PR #2316).
- PKIXCertPathReviewer.processQcStatements() only recognised the legacy ETSI TS 101 862 / RFC 3739 QC statements (QcCompliance, QcSSCD, QcLimitValue, pkixQCSyntax-v1), so a qualified certificate carrying the modern ETSI EN 319 412-5 statements (QcType, QcRetentionPeriod, QcPDS, QcCClegislation) or pkixQCSyntax-v2 in a critical qcStatements extension was reported as having an "unknown critical extension". These are now recognised and surfaced as notifications, QcType additionally listing the declared esign / eseal / web types, so the reviewer no longer flags such certificates. Applied to both the org.bouncycastle.pkix.jcajce and org.bouncycastle.x509 copies (issue #1239).
- An ECGOST3410-2012 key pair generated on one of the 256-bit GOST R 34.10-2001 named curves was stamped with the legacy GOST R 34.11-94 digest OID (1.2.643.2.2.30.1) instead of id-tc26-gost3411-12-256 (1.2.643.7.1.1.2.2). The shared GOST3410ParameterSpec(String) constructor defaults those curves to the 94 digest, which is correct for an ECGOST3410-2001 key but wrong for a 2012 one; the 2012 key-pair generator now remaps a 94 digest to the 2012-256 digest, so the public key, private key and their encodings all report the correct OID. The native 2012 curves are unaffected (issue #611).
- KeyFactory.getInstance("RSASSA-PSS") shared the generic RSA KeyFactorySpi, so keys built from the raw RSAPublicKeySpec / RSAPrivateKeySpec / RSAPrivateCrtKeySpec were stamped with the rsaEncryption AlgorithmIdentifier rather than id-RSASSA-PSS (RFC 8017 A.2.3): they reported "RSA" from getAlgorithm() and encoded with the wrong OID, even though KeyPairGenerator.getInstance("RSASSA-PSS") and the encoded-spec paths already produced id-RSASSA-PSS keys. The RSASSA-PSS KeyFactory now stamps id-RSASSA-PSS on keys generated from the raw RSA key specs; the plain RSA KeyFactory is unchanged (issue #1474).
- The "No CRLs found for issuer ..." exception thrown by BC's CertPathValidator (and X509RevocationChecker) when a revocation check came back empty gave callers no clue about why the lookup failed. The message now also lists the certificate's CDP URIs, the number of PKIXCRLStores / CertStores consulted, and the state of the network-fetch toggle (with a hint pointing at the property or at registering a store). When the toggle is on and every CDP URI fails, the per-URI causes are now propagated up instead of being silently swallowed. The "org.bouncycastle.x509.enableCRLDP" system property is now exposed as the Properties.X509_ENABLE_CRLDP constant (issue #1309).
- GOST3410ParametersGenerator's Procedure A'/B' inner loops resampled candidate values via `init_random.nextInt() * 2` / `init_random.nextInt() * 2 + 1`; the multiplication was evaluated in *int* arithmetic (wrapping modulo 2^32) before being widened to the surrounding `long`. The multiplications are now evaluated in `long` arithmetic (`* 2L` / `* 2L + 1`), so a large sampled value no longer wraps before the candidate is formed (issue #813).
- CertificateFactory ("BC", "X.509") returned null from generateCertificate(InputStream) / generateCRL(InputStream) for empty input or an empty PKCS#7 SignedData wrapper, contrary to the java.security.cert.CertificateFactory contract that mandates throwing when no certificate or CRL can be parsed - PR #459 covered the garbage-PEM and garbage-DER cases, this completes the empty-input residual. The single-value methods now throw a CertificateException / CRLException naming the failure, while generateCertificates / generateCRLs continue to return a possibly-empty Collection per their separate contract. Internal callers in PKIXCertPath that walked a multi-cert stream by looping until null now use a single generateCertificates call (issue #457).
- LocalizedMessage.getEntry (both the org.bouncycastle.i18n and org.bouncycastle.pkix.util copies) called ResourceBundle.getBundle(name, locale) without an override, so Java's default candidate-locale chain, which falls back to Locale.getDefault() when the requested locale has no matching properties file, would return a JVM-default-locale bundle to a caller who had explicitly asked for a different one - on a German system a test requesting Locale.ENGLISH received the German message and failed its literal-text assertion. Both classes now use ResourceBundle.Control.getNoFallbackControl(FORMAT_DEFAULT), so the lookup falls through to the base English bundle rather than the JVM default when no _en file is shipped (issue #2249).
- The BC provider's ML-DSA Signature implementation resolved a public key supplied by another provider through the legacy PQC PublicKeyFactory rather than org.bouncycastle.crypto.util.PublicKeyFactory, so initVerify with a non-BC ML-DSA public key failed with an exception. The conversion now goes through the correct factory (issue #2287).
- FalconKeyPairGeneratorSpi.getNameFromParams was inconsistent: FalconParameterSpec returned an upper-cased name while NamedParameterSpec was lower-cased, leaving NamedParameterSpec inputs unable to resolve any Falcon variant. FalconParameterSpec now preserves the canonical lower-case algorithm name, so both spec types now work (issue #2194).
- ProvOcspRevocationChecker was silently ignoring OCSP response signature verification failures when an OCSP response was supplied via PKIXRevocationChecker.setOcspResponses(). The checker now raises a CertPathValidatorException when the response signature fails to validate.
- The streaming ASN.1 generators (BERSequenceGenerator, BEROctetStringGenerator, DERSequenceGenerator) wrote the tagged-object identifier as a single octet, so a tag number greater than 30 silently produced a corrupt encoding (the low five bits collided with the X.690 8.1.2.4 high-tag-number escape). The tagged header is now emitted through the same identifier encoding used by ASN1OutputStream, so high tag numbers encode correctly in both the explicit and implicit (X.690 8.14.2 / 8.14.3) forms. Output for tag numbers 0 to 30 — including all the CMS uses — is unchanged.
- The public ECJPAKECurve constructor documented that "n\*h must equal the order of the curve" but performed no such check, so a user-supplied group with a wrong order or cofactor was accepted. Since computing the exact point count is impractical, the constructor now checks the implied order n\*h against the Hasse bound for the field size ((q + 1 - n\*h)^2 \<= 4q), rejecting wildly wrong n or h values; the pre-approved ECJPAKECurves groups are unaffected.
- RFC3394WrapEngine.init and RFC5649WrapEngine.init (the base engines behind AESWrap / AESWrapPad / ARIAWrap / CamelliaWrap / SEEDWrap) silently ignored a CipherParameters argument that was neither a KeyParameter nor a ParametersWithIV, leaving the engine unkeyed so the next wrap/unwrap failed later with an opaque NullPointerException. They now reject an unrecognised parameter type up front with "invalid parameter passed to \<cipher\> init - \<class\>", matching the behaviour of the other org.bouncycastle.crypto.engines block ciphers.
- X509CertificateFormatter was indenting the basicConstraints pathLenConstraint line incorrectly, dropping the 23-space prefix shared with other extension lines. The line now uses the same pad as the surrounding output (issue #2214).
- A wide audit of catch-and-rethrow sites that dropped the original cause when rewrapping as IllegalArgumentException, IllegalStateException, or IOException has been carried out across core, prov, pkix, pg, mail/jmail, mls and tls. The affected sites now chain the cause via org.bouncycastle.util.Exceptions so the full stack trace is preserved, while keeping the existing message text unchanged (issue #2239 / PR #2250).
- PGPPublicKey.getValidSeconds() returned a stale expiration time when an earlier self-signature carried a Key Expiration Time subpacket and a more recent self-signature omitted it; per RFC 4880 5.2.4.1 the latest self-signature wins, so the absence of the subpacket on the newer signature now correctly cancels the expiry and the method returns 0 (issue #1749).
- The Argon2 memory size exponent bounds check, capped by the "org.bouncycastle.argon2.max_memory_exp" property, is now applied at key-derivation time (PGPUtil.makeKeyFromPassPhrase) rather than during S2K packet parsing, so an out-of-range exponent in one ESK packet no longer makes a whole stream unparseable: decryption fails with a PGPException and other ESK packets can still be attempted, on both the SKESK and secret-key paths. The enforced lower bound now also matches RFC 9106 sec. 3.1, which requires the memory size m to be at least 8\*p kibibytes; previously only an exponent below 3 was rejected, so an Argon2 S2K with parallelism 4 and exponent 4 was accepted at this layer. That bound equals the floor the S2K.Argon2Params constructor already enforces, so the two paths now agree (issue #2283 / PR #2322).
- ArmoredInputStream's base64 decoder defeated its own invalid-character check in the two-pad ("XX==") group: the two decoding-table lookups were masked to unsigned values before the "\< 0" guard, so the 0xff sentinel for a non-alphabet character became 255 and the guard never fired. A final armor group such as "!!==" was decoded to a junk byte rather than rejected, while the one-pad ("XXX=") and no-pad ("XXXX") groups (and Base64Encoder) already rejected it. The mask has been removed so all three groups validate consistently.
- S/MIME signing of an attachment-only MimeMessage produced a signed body with empty content. SMIMEGenerator.makeContentBodyPart(MimeMessage) rebuilt the content body part by re-wrapping message.getDataHandler().getDataSource(), a workaround for a javax.mail change affecting stream-backed attachments; for an object-backed message whose content type has no object DataContentHandler, getDataSource() returns a synthetic DataHandlerDataSource and re-wrapping it yields a body part that writes nothing, so writeTo() throws "no object DCH" and the signature is computed over empty content. The re-wrap is now applied only to a genuine DataSource, an object-backed DataHandler being carried through unchanged, so attachment-only messages sign correctly on both javax.mail and jakarta.mail (issue #1432).
- PEMParser failed to parse a "BEGIN PRIVATE KEY" block carrying OpenSSL-legacy encryption headers (Proc-Type: 4,ENCRYPTED / DEK-Info), throwing "corrupted stream" while ASN.1-decoding the ciphertext. The PRIVATE KEY parser now honours those headers and returns a PEMEncryptedKeyPair whose decryptKeyPair() yields a PEMKeyPair holding the decrypted PKCS#8 PrivateKeyInfo (issue #1238).
- PKIXCertPathValidatorSpi (and its JDK 8+ revocation-checker-aware variant) threw a NullPointerException when validating against a TrustAnchor constructed with (caName, caPublicKey, nameConstraints) instead of an X509Certificate, because the trust anchor's certificate encoding was always validated up front. The check is now skipped when no certificate is supplied, allowing name-and-key trust anchors to validate as expected (issue #1420).
- PKCS12PfxPdu.isMacValid threw ClassCastException when the PFX used PBMAC1 (id-PBMAC1) for integrity, because JcePKCS12MacCalculatorBuilderProvider tried to parse the algorithm parameters as PKCS12PBEParams. The provider now dispatches to JcePBMac1CalculatorBuilder for id-PBMAC1, and isMacValid compares only the inner MAC digest bytes for PBMAC1 (RFC 9579 sec. 6 leaves the MacData salt and iterations unused, so producers may write arbitrary placeholder values) — PBMAC1 PFX files written by OpenSSL and BCJSSE now verify correctly.
- JcaPGPKeyConverter.getPublicKey threw "InvalidParameterSpecException: Not a supported curve" on JDK 11 when the underlying JCE provider was Sun's, because the converter unconditionally fed the X9.62 OID-encoded form to AlgorithmParameters and Sun's CurveDB couldn't resolve it. The converter now resolves the curve name first via ECNamedCurveTable.getName(...) and only falls back to the OID encoding when the provider doesn't recognise the name (issue #1230).
- CertPathBuilder could recurse without bound, giving a StackOverflowError on small stacks, when CRL revocation was enabled and a CRL had multiple candidate signers - several trust-anchor roots sharing the issuer DN, say. A re-entry guard in RFC3280CertPathUtilities.processCRLF now breaks the cycle, and candidates whose path cannot be built are skipped rather than aborting the whole check. As a follow-up, where the CRL carries an authorityKeyIdentifier with a keyIdentifier field, processCRLF narrows the candidate signer set by SubjectKeyIdentifier (RFC 5280 sec. 5.2.1); without that the wall time grew O(N^depth) across N roots sharing the issuer DN, reported on the issue as some seven minutes for N=6 (issue #2291).
- OpenSSHPrivateKeyUtil.encodePrivateKey now wraps ECDSA keys in the openssh-key-v1 envelope (matching the Ed25519 path) instead of emitting a raw RFC 5915 ECPrivateKey SEQUENCE, so the output is loadable by OpenSSH and JSCH (issue #2240).
- X500Name string parsing rejected RDNs whose attributeValue contained an unescaped '=', e.g. "CN==^\_^=" or "CN=foo=bar", with "badly formatted directory string". RFC 4514 sec. 3 lists '=' (0x3D) as a valid stringchar, so only the FIRST '=' separates the attributeType from the attributeValue. IETFUtils now rejoins any subsequent '='-split tokens, matching the behaviour of javax.security.auth.x500.X500Principal (issue #2226).
- AuthorityKeyIdentifier (id-ce 35) construction and parsing now enforce the RFC 5280 sec. 4.2.1.1 constraint that authorityCertIssuer and authorityCertSerialNumber MUST both be present or both be absent. The ASN1Sequence parse path and the (byte[], GeneralNames, BigInteger), (SubjectPublicKeyInfo, GeneralNames, BigInteger) and (GeneralNames, BigInteger) public constructors all throw IllegalArgumentException when only one of the two fields is supplied (issue #2036).
- TBSCertList, TBSCertificate and AttributeCertificateInfo parsing, plus the V1/V3 TBSCertificate, V2 TBSCertList and V2 AttributeCertificateInfo generators, now enforce the RFC 5280 sec. 4.1.2.4 / 5.1.2.3 and RFC 3281 sec. 4.2.3 requirement that the issuer field contain a non-empty identifier. Empty X.500 issuer names, empty v1 GeneralNames AttCertIssuer values, and V2Form AttCertIssuer values lacking issuerName / baseCertificateID / objectDigestInfo are now rejected with an Illegal{Argument,State}Exception instead of being silently accepted. As a side fix, V2Form parsing no longer throws ArrayIndexOutOfBoundsException on an empty SEQUENCE input (issue #2010).
- JndiDANEFetcherFactory now uses DirContext.list() rather than listBindings() to enumerate \_smimecert entries, so each result is delivered as a NameClassPair (string-only) instead of a Binding whose getObject() materialises a Java object from the directory's reply. The factory only ever consumed the entry's name from the binding; switching to list() preserves identical behaviour for legitimate DNS responses while removing the JNDI-deserialisation attack surface that would otherwise apply if the API were redirected at a hostile JNDI provider (issue #239).
- BcRSAContentSignerBuilder and BcRSAContentVerifierProviderBuilder unconditionally instantiated RSADigestSigner (PKCS#1 v1.5) regardless of the supplied signature algorithm OID, so when an id-RSASSA-PSS AlgorithmIdentifier was passed in the lightweight Bc\* operator path produced and verified PKCS#1 v1.5 bytes — wire-incompatible with the JCE RSASSA-PSS path and rejected by external validators (e.g. EU DSS). Both builders now detect id-RSASSA-PSS and construct a PSSSigner from the RSASSAPSSparams (hashAlgorithm / mgf1 hash / saltLength / trailerField=1) so Bc-side signing and verification round-trip correctly with the JCE side and with RFC 8017 PSS implementations generally (issue #721).
- BCStyle and RFC4519Style now reject countryName (BCStyle.C / RFC4519Style.c) and, for BCStyle, jurisdictionCountry (JURISDICTION_C) attribute values whose length is not exactly 2 when constructing a new X500Name (via X500NameBuilder.addRDN or the X500Name(String) constructor). RFC 5280 sec. 4.1.2.4 / X.520 specify countryName as PrintableString (SIZE (2)) and CAB Forum Baseline Requirements 7.1.4.2.1 narrows it to a valid ISO 3166-1 alpha-2 code, so values such as "USA" now throw IllegalArgumentException at build time rather than encoding a non-spec value that downstream consumers would reject. Parsing of existing DER-encoded names containing a non-conforming country code is deliberately still permitted, so already-issued certificates in the wild remain readable (issue #2011).
- BCStyle and RFC4519Style now reject commonName (BCStyle.CN / RFC4519Style.cn) attribute values longer than 64 characters when constructing a new X500Name (via X500NameBuilder.addRDN or the X500Name(String) constructor). RFC 5280 sec. A.1 / X.520 specify commonName as DirectoryString { ub-common-name } with ub-common-name = 64, and OpenSSL / Microsoft CryptoAPI / GnuTLS / CAB Forum BR-aware validators all reject longer values. Names whose CN exceeds 64 characters now throw IllegalArgumentException at build time rather than encoding a value that downstream consumers will reject. Parsing of existing DER-encoded names containing an over-length CN is deliberately still permitted, matching the leniency split applied to countryName (issue #750).
- DefaultDigestAlgorithmIdentifierFinder.find(AlgorithmIdentifier) returned the wrong digest for the IANA-namespaced composite ML-DSA + classical signature OIDs: every entry mapped to SHA-512 regardless of the scheme's actual prehash. The mappings now reflect the per-scheme prehash that the composite SignatureSpi feeds the inner signers (the OID name suffix): SHA-256 for \*\_SHA256 variants, SHAKE-256 for id_MLDSA87_Ed448_SHAKE256, SHA-512 for \*\_SHA512 variants.
- The class-level javadoc around CMS parsers and streaming generators has been updated to explicitly describe how it treats the underlying streams passed in.
- X509CertificateImpl.hasUnsupportedCriticalExtension() reported a critical extendedKeyUsage (id-ce 37) extension as unsupported, so loading such a certificate through the BC CertificateFactory returned true where the JDK provider returned false. RFC 5280 sec. 4.2.1.12 explicitly permits extendedKeyUsage to be marked critical, and the BC X509Certificate implementation fully recognises it (getExtendedKeyUsage()); the OID has been added to the skip list in hasUnsupportedCriticalExtension() so the BC and JDK providers now agree (issue #1796).
- The BC X.509 CertificateFactory (Provider "BC", "X.509"/"X509") previously recognised only the RFC 2315 PKCS#7 SignedData ContentType OID (1.2.840.113549.1.7.2) when extracting embedded certificates and CRLs from a SignedData wrapper, so generateCertificate{s} / generateCRL{s} returned nothing (or threw "sequence wrong size for a certificate") for a GM/T 0010-2012 SM2 SignedData wrapper (ContentType 1.2.156.10197.6.1.4.2.2). Both SignedData ASN.1 structures are identical apart from the outer ContentType OID, so the factory now treats the SM2 OID equivalently and walks the embedded certificate / CRL sets the same way. New ASN.1 constants for the full GM/T 0010 SM2 content-type arc (1.2.156.10197.6.1.4.2.{1..6}) have been added to GMObjectIdentifiers (issue #1355).
- ESTService.getCSRAttributes treated a server response of 204 No Content or 404 Not Found as "no attributes available" and returned null, but did not drain the response body before letting the surrounding finally block close it. When the server attached a body to the 404 (e.g. a JSON error message), ESTResponse's underlying LimitedInputStream then threw "Stream closed before limit fully read" on close and the caller saw an opaque IOException-wrapping ESTException instead of the 404 status they could act on. The 204 / 404 branches now drain the body via Streams.drain before returning, so the close path completes cleanly and the call returns a null CSRAttributesResponse as documented (issue #781).
- JceOpenSSLPKCS8DecryptorProviderBuilder cast the PBES2 key-derivation-function parameters blind to PBKDF2Params, so an EncryptedPrivateKeyInfo whose KDF inside PBES2 was scrypt (RFC 7914, e.g. anything produced by "openssl pkcs8 -topk8 -scrypt") failed to decrypt with "DLSequence cannot be cast to PBKDF2Params". The builder now dispatches on the KDF algorithm OID: id-PBKDF2 takes the existing PBKDF2 path, id-scrypt parses the parameters as ScryptParams and derives the key via SCrypt.generate (the password is encoded as UTF-8 to match OpenSSL's raw-bytes treatment). PBKDF2-based PBES2, PKCS#5 PBES1 and PKCS#12 PBE paths are unchanged (issue #400).
- RFC3280CertPathUtilities.processCRLB2 (in both prov and pkix) emitted an opaque AnnotatedException "No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point." when the CRL's issuingDistributionPoint did not match the cert's CRL distribution point names, with no way for an operator to tell which CRL had been returned for which DP. The message now appends both name lists, e.g. ". cert DP names: [6: http://crl3.example/foo.crl, 6: http://crl4.example/foo.crl]; CRL IDP names: [6: http://crl4.example/bar.crl]", letting the cause of the mismatch be diagnosed without re-running with extra logging. Existing assertion sites in NistCertPathTest / NistCertPathTest2 / PKITSTest were updated to use prefix-matching against the original message (issue #800).
- JceInputDecryptorProviderBuilder previously assumed the supplied AlgorithmIdentifier parameters were either an ASN1OctetString (raw IV) or GOST28147Parameters, so init() failed with "DLSequence cannot be cast to ASN1ObjectIdentifier" (via the GOST fallback) on an AES-GCM (or AES-CCM) AlgorithmIdentifier carrying GCMParameters / CCMParameters. The builder now dispatches on the algorithm OID: id-aes{128,192,256}-GCM and id-aes{128,192,256}-CCM parse the parameters as GCMParameters / CCMParameters and init the cipher via GCMParameterSpec(icvLen\*8, nonce); the existing IV and GOST paths are unchanged (issue #1510).
- BCStyle and RFC4519Style now accept "DN", "DNQ" and "dnQualifier" as parser aliases for the dnQualifier attribute (OID 2.5.4.46), so new X500Name(principal.toString()) round-trips when the underlying JDK stringifies the attribute using any of those short forms (issue #1622).
- BCStyle and RFC4519Style now accept "S" as a parser alias for the stateOrProvinceName attribute (OID 2.5.4.8), in addition to the RFC 2253/4514 short form "ST". Microsoft's CertNameToStr emits "S=" for 2.5.4.8 (its documentation notes this differs from the RFC 1779 key name "ST"), so DN strings produced by Windows tooling previously failed to parse with "Unknown object id - S - passed to distinguished name". Encoding is unchanged — BC still emits the canonical "ST" symbol on output (issue #1301).
- Six S/MIME content-handler classes in the bcjmail tree (org.bouncycastle.mail.smime.handlers) each carried a leftover "import java.awt.datatransfer.DataFlavor;" line that survived the migration to Jakarta Activation 2.x. The import was unused - every reference routes through jakarta.activation.ActivationDataFlavor, a standalone class in 2.x that no longer extends the awt type - but it nevertheless forced Android and other awt-less JVMs to pull a non-existent class onto the classpath at load time. The imports have been removed and the bcjmail tree now has zero java.awt references across main and test, so Android consumers with a Jakarta Activation 2.x runtime no longer need a DataFlavor shim. The legacy bcmail tree cannot be cleaned up the same way, javax.activation.ActivationDataFlavor extending the awt type by upstream contract, so Android users should consume bcjmail (issue #242).
- CMS EnvelopedData with a BSI TR-03111 ECKA-EG-X963KDF key agreement failed both encode and decode: JceKeyAgreeRecipientInfoGenerator threw "Unknown key agreement algorithm" on generate, and JceKeyAgreeRecipient's parallel branch silently fell through to a null UserKeyingMaterialSpec, producing the wrong shared secret and "checksum failed" on the AES key unwrap. The underlying agreement is structurally identical to dhSinglePass_stdDH\_\*kdf_scheme, and BSI TR-03109-3 / ICAO 9303-11, the canonical consumers of ECKA-EG-in-CMS, specify the RFC 5753 ECC-CMS-SharedInfo format for the KDF input, so the six BSI ecka_eg_X963kdf\_\* OIDs have been added to the EC dispatch table in CMSUtils and both directions now route through the existing RFC 5753 KeyMaterialGenerator (issue #790).
- The package-private org.bouncycastle.pkix.ASN1PKIXNameConstraintValidator carried a near-verbatim copy of org.bouncycastle.asn1.x509.PKIXNameConstraintValidator in core. The pkix-side org.bouncycastle.pkix.PKIXNameConstraintValidator facade now delegates directly to the core class — matching the pattern already used by org.bouncycastle.jce.provider.PKIXNameConstraintValidator in prov — and the duplicate has been removed.
- SMIMESignedGenerator.generate(MimeBodyPart) producing a multipart-signed message containing a nested multipart subpart could not be verified in-process: SMIMESigned.getSignerInfos().verify(...) threw CMSSignerDigestMismatchException because SMIMEUtil.outputBodyPart's verify-side writer skipped the CRLF separator the signer had emitted between an inner multipart's closing boundary and the next outer boundary. The verify side delegated that separator to SMIMEUtil.outputPostamble, which reads from parent.getRawInputStream() - only available once the part has been serialized to bytes - and so silently emitted nothing for in-memory parts. outputPostamble now emits a single CRLF when the raw stream is unavailable, matching the signing side; the postamble-preservation path for parsed-from-bytes parts is unchanged, so existing interop verification continues to work (issue #542).
- PKIXCertPath.sortCerts - the convenience reorder used by generateCertPath(List) when the supplied collection is not already in end-entity-to-root order - fell back to the unsorted input for certain orderings, such as [end-entity, root, intermediate] where it should have produced [end-entity, intermediate, root]. The end-entity-detection loop mutated its working list while iterating: the inner "is anyone's issuer this cert's subject?" scan walked the mutating list, so once an end-entity was removed its parent intermediate had nothing pointing to it and was misclassified as a second end-entity, and the outer index incremented past the element that had shifted down. The fix snapshots the input for the inner scan and decrements the outer index after a remove, restoring best-effort ordering for inputs the algorithm previously gave up on (issue #1269).
- DefaultAlgorithmNameFinder.getAlgorithmName had no mappings for the four EdEC OIDs (id_Ed25519, id_Ed448, id_X25519, id_X448), so callers got the bare OID string (e.g. "1.3.101.112") instead of the algorithm name. This was out of step with DefaultSignatureNameFinder and DefaultSignatureAlgorithmIdentifierFinder which both map the signature OIDs to their names. ED25519 / ED448 / X25519 / X448 have been added to DefaultAlgorithmNameFinder's static table (issue #2306).
- The published Maven Central jars (main, -sources, -javadoc) for every Gradle-built subproject (bcprov, bcpkix, bcutil, bcpg, bctls, bcmls, bcmail, bcjmail) now embed the project's LICENSE.md at META-INF/LICENSE.md so automated OSS compliance scanners (ScanCode, FOSSology, etc.) can recover the license terms from the artifact alone — previously the -sources.jar in particular carried no license information and was flagged as "Unlicensed" / "Unknown License" by CI scanners (issue #2303).
- ECIESKEMExtractor.extractSecret crashed with a NullPointerException ("Cannot invoke ECFieldElement.getEncoded() because getAffineXCoord() is null") when the supplied encapsulation decoded to the point at infinity — the SEC1 / X9.62 single-byte 0x00 encoding — because the subsequent hTilde.getAffineXCoord() returned null on the infinity point. The extractor now routes any infinity hTilde (whether reached directly from a 0x00 encapsulation or indirectly via a low-order ephemeral that collapses under the static-ephemeral scalar multiplication) to an all-zero implicit-rejection key of the configured key length, so a hostile encapsulation produces a key that won't decrypt the subsequent payload rather than crashing the decapsulation service.
- IETFUtils.rDNsFromString, and so the X500Name(String) constructor, treated each \HH escape inside a DN attributeValue as an independent Java char, so a multi-byte UTF-8 character spelled out as consecutive hex escapes produced a String of one char per byte, then DER-encoded as a malformed UTF8String. RFC 4514 sec. 2.4 lets any byte be escaped as \HH and RFC 5280 sec. 4.1.2.4 mandates UTF-8 for the underlying directoryString, so a \HH run is a UTF-8 byte sequence; unescape now accumulates consecutive escapes as bytes and decodes the run through Strings.fromUTF8ByteArray. Relatedly, it previously dropped a backslash escape that began a hex pair but was not completed by a second hex digit, and the abandoned half-pair could corrupt a following valid escape; a lone hex digit is now rejected with IllegalArgumentException (issue #1061).
- SignerInformation.verify failed to verify a GOST signature whose signedAttributeSet was null when the SignerInformation came from CMSSignedDataParser, which leaves it with a pre-computed resultDigest and no content. JcaContentVerifierProviderBuilder.createRawSig built the NONE-prefixed signature algorithm name and asked the JCE for a matching Signature service so it could expose a RawContentVerifier, but BC registered no such service, so the verifier degraded to a plain SigVerifier which the doVerify path fed no bytes, returning false. The provider now registers NONEWITHECGOST3410 and its 2012-256 / 2012-512 variants as NullDigest-backed siblings of the existing SignatureSpi classes, so the raw-verify path applies the pre-computed hash directly through ECGOST3410Signer.verifySignature and parser-driven direct-signature verification succeeds (issue #1501).
- ASN1UTCTime and ASN1GeneralizedTime now reject structurally malformed content on decode (non-digit or out-of-range fields, illegal lengths, missing/garbage terminators) rather than parsing it into a time object whose getDate() returns a nonsensical date or throws. ASN1UTCTime.createPrimitive / ASN1GeneralizedTime.createPrimitive validate well-formedness via the new org.bouncycastle.asn1.ASN1TimeFormat helper; legal-but-non-DER formatting (missing seconds, "+hhmm" offset, trailing-zero fraction, local-time GeneralizedTime) is still parsed leniently and the write-side DER gate (Properties.ASN1_ALLOW_NON_DER_TIME) is unchanged. Among other things this rejects a UTCTime-shaped (13-character, 2-digit-year) value smuggled inside a GeneralizedTime, as seen in CRL thisUpdate/nextUpdate fields in the wild (issues #1973, #2040, #2321).
- PKCS12KeyStoreSpi.processKeyBag and PKCS12PBMAC1KeyStoreSpi.processKeyBag threw a NullPointerException when loading a keystore containing an RFC 7292 sec. 4.2.1 keyBag (unencrypted PrivateKeyInfo) that either carried no bagAttributes or carried bagAttributes without a localKeyId — getBagAttributes() and the recovered localId were dereferenced unconditionally, unlike the sibling processShroudedKeyBag / processSecretBag which already guard both. Both keyBag handlers now skip the attribute scan when bagAttributes is absent and stash a localKeyId-less key under the "unmarked" alias, matching the shrouded-key-bag path, so such a keystore loads instead of failing on parse.
- OtherName (RFC 5280 sec. 4.2.1.6), SafeBag (RFC 7292 sec. 4.2) and SignerInfo (RFC 2315 sec. 9.2, the legacy PKCS#7 type) getInstance now validate the decoded SEQUENCE length — exactly 2 for OtherName, 2 or 3 for SafeBag, 5 to 7 for SignerInfo — and route element extraction through the typed getInstance helpers. A structurally invalid SEQUENCE (wrong element count, or an element of the wrong ASN.1 type) now fails fast with "Bad sequence size: \<n\>" / an IllegalArgumentException, rather than leaking an ArrayIndexOutOfBoundsException or ClassCastException out of the parse, matching the strict-parse behaviour of the neighbouring x509 / pkcs ASN.1 types.
- The OpenSSL PEM parsing path hardened its handling of malformed encryption metadata. A PEM block whose "Proc-Type: 4,ENCRYPTED" header was present but whose "DEK-Info" header was missing, or whose DEK-Info value lacked the IV component, previously leaked a NullPointerException (KeyPairParser) or NoSuchElementException out of PEMParser; both the "RSA/DSA/EC PRIVATE KEY" (KeyPairParser) and "PRIVATE KEY" (PrivateKeyParser) paths now reject such input with a PEMException ("malformed PEM data: missing or invalid DEK-Info header"). Separately, PemReader.readPemObject wrapped a malformed base64 body in a DecoderException (a RuntimeException) that escaped the method's declared IOException contract; the Base64 decode is now caught and re-thrown as an IOException with the original cause attached.
- The OpenSSL PEMParser path for the traditional "DSA PRIVATE KEY" format silently ignored the version field of the DSAPrivateKey SEQUENCE, so a key whose version was any value other than 0 parsed without complaint. The sibling RSA path already rejects an out-of-range version ("wrong version for RSA private key") and BC's own writer always emits version 0, so the DSA parser now likewise rejects a non-zero version with "wrong version for DSA private key", bringing it into line with the RSA/EC traditional-key parsers (issue #2319).
- Follow-up to CVE-2026-5588: the legacy id_alg_composite CompositeVerifier (org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder, used by X509CertificateHolder.isSignatureValid, CMS and TSP) iterated the component count from the supplied signature sequence rather than from the key, so although the earlier fix rejected an empty signature sequence, a composite signature truncated to a verifying prefix (e.g. stripped of its post-quantum or its classical component) still verified. The verifier now requires the signature to carry exactly one component for every component key, rejecting both under- and over-length composite signatures. The final-draft (IANA-OID) composite path was unaffected — it parses a fixed-length concatenation and already verifies every component.
- The XMSS and XMSS^MT public-key converters in PublicKeyFactory (the raw RFC 9802 / RFC 8391 SubjectPublicKeyInfo form, which prefixes the key material with a 4-octet parameter-set OID) leaked a RuntimeException out of the createKey / BouncyCastleProvider.getPublicKey decode path on a malformed key: a public key shorter than the 4-octet OID prefix threw ArrayIndexOutOfBoundsException, and one carrying a valid parameter-set OID but truncated root/seed material threw IllegalArgumentException ("public key has wrong size"). Both are reachable when decoding an untrusted certificate, PKCS#8 or SubjectPublicKeyInfo through the BC provider. The converters now reject such input with an IOException, matching the declared contract and the strict-parse behaviour of the neighbouring stateful-hash converters.
- BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo) and getPrivateKey(PrivateKeyInfo) — the provider's internal entry points for turning a decoded key into a JCA PublicKey / PrivateKey, reached when parsing an untrusted certificate, PKCS#12 / BCFKS keystore entry or wrapped key — could leak a RuntimeException (typically a NullPointerException from a key-info converter handed a structurally degenerate SubjectPublicKeyInfo / PrivateKeyInfo, for example one with empty or truncated key material) out of their declared IOException contract. Both methods now catch a converter's RuntimeException and re-throw it as an IOException with the original cause attached, so a malformed key surfaces as the checked exception callers already handle rather than an uncaught crash. The per-algorithm converters are unchanged; this is a defence-in-depth guard at the shared decode boundary.
- S/MIME streaming operations buffer decrypted, decompressed and signed plaintext to backing temp files. These were created with File.createTempFile, which honours the process umask and so typically leaves the files world-readable (mode 0644) on POSIX systems, allowing other local users on a shared host to read the plaintext before cleanup. The temp files created by SMIMEUtil and SMIMESignedParser are now created through Files.createTempFile, which restricts them to the owner (0600 on POSIX, owner-only ACL on Windows). The java.nio.file call is isolated in a package-private TempFileFactory, so the legacy pre-Java-7 builds - where java.nio.file is unavailable - fall back to the historical File.createTempFile via jdk1.4 / jdk1.5 source overrides (issue #2326).
- HQCEngine.decaps bounded its Fujisaki-Okamoto implicit-rejection conditional-move by the Reed-Solomon message length k (16 bytes for HQC-128, 24 for HQC-192) rather than by the full 32-byte shared secret. On a re-encryption mismatch this left the trailing bytes ss[k..31] holding K' = G(H(pk) || m' || salt), a deterministic function of the decoder output m' of the attacker-supplied ciphertext, rather than the rejection secret. That gave an adaptive attacker with a decapsulation oracle a plaintext-checking / decoding-result oracle on the underlying PKE, defeating the implicit-rejection property and breaking IND-CCA2 for HQC-128 and HQC-192 (HQC-256 was unaffected, as k == 32 there). The conditional-move now covers all 32 bytes of the shared secret, so on re-encryption failure every output byte depends only on the rejection PRF and the ciphertext; the success path is unchanged.
- OpenPGP AEAD decryption (SEIPDv2 / OpenPGP v6 and the v5 AEAD packet) skipped verification of the trailing message tag for chunk-aligned messages. RFC 9580 sec. 5.13.2 ends an AEAD message with a final authentication tag over the total plaintext length so that truncation at a chunk boundary is detectable, but the decrypting stream verified it only when the last data chunk was short: where the plaintext was an exact multiple of chunkLength the final tag was pre-read into the look-ahead, never passed to doFinal, and the stream returned a clean EOF. As PGPEncryptedData.verify() returns true unconditionally for AEAD there was no backstop, so an attacker able to tamper with the ciphertext could strip trailing chunks plus the final tag, fix up the unauthenticated outer packet length, and have the recipient accept the truncated plaintext as authentic. The final tag is now always verified before EOF is signalled, in both the Bc and Jce decryptors.
- The X-Wing hybrid KEM lightweight implementation (`org.bouncycastle.pqc.crypto.xwing`) shipped in the bcprov jar but was missing from the JPMS module descriptor, so module-path consumers (JDK 9+) could not reference it even though class-path consumers could. The package is now exported.
- The vestigial round-3 "Dilithium-AES" OIDs were registered in PublicKeyFactory and the BouncyCastleProvider key-info converter bridge but not in PrivateKeyFactory, so getPublicKey() decoded such a public key to one carrying null parameters while getPrivateKey() rejected it. There is no lightweight Dilithium-AES parameter set, the variants having been dropped in the ML-DSA migration, so these converters have been removed and both key-factory paths now consistently reject the OIDs. The remaining vestigial references went with them: the never-registered Base2_AES / Base3_AES / Base5_AES subclasses of DilithiumKeyFactorySpi, the DILITHIUM2/3/5-AES name mappings in the pkix finders, and the matching registrations in the legacy pre-1.5 source trees. The OID constants themselves remain in BCObjectIdentifiers.
- IESEngine stream mode (IES/ECIES/DHIES with no backing block cipher) derived the keystream K1 and the MAC key K2 from the key-derivation output using two different layouts: the ephemeral-sender path took K2 from a fixed prefix and K1 from the remainder, but the static-key path took K1 first and K2 from a message-length-dependent offset behind it. Because static-key mode reuses the same derivation input for every message, a single known-plaintext recovery of K1 then also exposed the MAC key of any shorter message, letting an attacker forge a ciphertext and tag from one observation. Both paths now use the fixed K2-first layout. The ephemeral ECIES wire format is unchanged; only the static-static stream-mode encoding changes, so ciphertext produced by earlier versions in that mode will no longer decrypt. Note static-key stream mode remains a deterministic many-time pad, unsuitable for more than one message, as the javadoc now says.
- SignedMailValidator used the CMS signingTime signed attribute as the certificate-path validation date, and a signer-supplied signingTime took precedence over any date set on the caller's PKIXParameters. Because signingTime is asserted by the signer and unauthenticated in the absence of a trusted timestamp, certificate expiry and revocation were evaluated at a signer-chosen instant, so a message back-dated to before the signing certificate's expiry or revocation validated as if the certificate were still good. A date explicitly set on the supplied PKIXParameters now takes precedence, so a caller can pin a trusted validation instant and have such a signature rejected; with no date set the behaviour is unchanged, the chain being validated as of the signing time so legitimately old signatures still verify. The security note has been added to the constructor javadoc.
- The PKIXRevocationChecker OCSP path accepted a stapled OCSP response (supplied via PKIXRevocationChecker.setOcspResponses) that was validly signed but not bound to the certificate being checked. When no SingleResponse in the response matched the certificate's CertID, the checker fell through and returned success, treating the certificate as not revoked. An attacker holding a revoked certificate could therefore staple an unrelated "good" response from the same issuer (for example one covering a different serial number) and pass revocation checking. ProvOcspRevocationChecker now fails over when no SingleResponse matches the certificate's CertID, so CRL fallback runs instead of the response being silently accepted, matching the binding the network-fetch path already enforces via OcspCache.
- The MLS wire decoder (MLSInputStream) allocated the buffer for an opaque field directly from the attacker-declared Varint length - up to 0x3FFFFFFF (~1 GiB) - before checking that the input held that many bytes. Because opaque fields appear in the first bytes of unauthenticated structures (PublicMessage, KeyPackage, Welcome, PrivateMessage), a few-byte message could force a ~1 GiB heap allocation prior to any signature or MAC verification, and a handful of concurrent messages could exhaust the heap. The declared length is now validated against the bytes actually remaining in the input before the buffer is allocated (matching the existing check in slice()), so an over-long length is rejected with an IOException rather than driving a large allocation.
- LMS/HSS (RFC 8554 / NIST SP 800-208) signature parsing leaked a NullPointerException out of its declared IOException contract when the attacker-supplied signature carried an LM-OTS or LMS parameter-set type code outside the registered table: LMOtsSignature.getInstance and LMSSignature.getInstance looked the code up with a Map.get that returns null for an unknown one and immediately dereferenced the result to size the C, y and path buffers. Because the public verify-prep methods reached from Signature.verify and the lightweight verify catch only IOException, the exception propagated out of verify - a remote denial of service reachable when verifying a malformed signature, for example one carried in a certificate. Both parse sites now reject an unknown type code with an IOException, matching the public-key parse which already did so.
- Several lightweight PQC signature verifiers threw an unchecked exception instead of returning false when handed a malformed or truncated signature. FalconSigner.verifySignature read the signature header byte and computed the nonce/signature split with no length check; MayoSigner, SnovaSigner and QRUOVSigner indexed the fixed-size signature - and, for QR-UOV, copied it into a parameter-set-sized buffer - before validating its length; and the stateful XMSSSigner, XMSSMTSigner, LMSSigner and HSSSigner let the decode exception escape verifySignature. All now reject a malformed signature by returning false, matching MLDSASigner, HawkSigner, FaestSigner and the SLH-DSA / UOV / HAETAE / MQOM verifiers which already guarded, closing a denial of service reachable wherever an attacker-supplied PQC signature is verified.
- PQC public-key and private-key parameter classes that decode a key from a raw byte[] did not validate the encoding length against the parameter set, so a too-short or wrong-length encoding was accepted and the offset computed from the parameter set then overran it, raising an ArrayIndexOutOfBoundsException out of a later crypto operation instead of a clean rejection at decode. For the signature schemes this crashed verification, most directly for a malformed ML-DSA or Falcon issuer certificate exercised during certification-path validation. MLDSAPublicKeyParameters, in both the canonical and the deprecated copy, accepted any encoding longer than 32 bytes, and FalconPublicKeyParameters stored H with no length check at all; both now reject a malformed length at construction, as MLKEMPublicKeyParameters and SLHDSAPublicKeyParameters already did. The same check was added to the remaining PQC public-key classes that lacked it - MAYO, SNOVA, QR-UOV, HAWK, HAETAE, SQIsign, legacy SPHINCS-256, and the FrodoKEM, HQC, NTRU, NTRU+, SNTRUPrime, NTRU-LPRime, SABER and X-Wing KEMs - plus the matching fixed-length private-key constructors, and to both Classic McEliece implementations. NewHope's class is a dual-role carrier for the two RLWE exchange messages, so its bound is enforced where each role is known.
- The CMS container parse path was hardened so that a structurally malformed or absent inner content surfaces as the declared CMSException rather than a raw RuntimeException. The byte[] and InputStream entry points route the outer ContentInfo through CMSUtils.readContentInfo, but the inner body was re-interpreted unguarded: CMSAuthEnvelopedData and CMSAuthenticatedData re-parsed it with getInstance, leaking IllegalArgumentException on an invalid inner element, while CMSCompressedData and CMSDigestedData reached the encapsulated content through a cast to ASN1OctetString, leaking ClassCastException - all reachable when parsing untrusted CMS. The casts are now getInstance calls, and every guarded inner getInstance across the six container classes reports a malformed inner element as CMSException("Malformed content.") and an absent one as CMSException("Missing content."), each carrying the original cause. CMSCompressedData.getContentStream is now declared to throw CMSException; CMSEncryptedData(ContentInfo) is not, and is documented as the one container still surfacing a raw IllegalArgumentException.
- The OpenPGP signature subpackets Features, TrustSignature, SignatureTarget, RevocationKey and RevocationReason read a fixed offset of their body from their accessors but did not validate the body length when parsed. SignatureSubpacketInputStream accepts a subpacket whose length field is 1 - just the type octet, leaving an empty body - so a malicious key or signature carrying a truncated such subpacket decoded cleanly and then threw an ArrayIndexOutOfBoundsException later when an application read it, for example checking the Features of a received key's self-signature. All five now validate their body length in the wire-parse constructor and reject a truncated subpacket with an IllegalArgumentException at decode time, surfaced by the parser as a MalformedPacketException, matching IssuerFingerprint and IntendedRecipientFingerprint. The value-based constructors are unchanged.
- ElGamalEngine performed no validation of the two ciphertext components on decryption: the first component gamma was raised to the static, private-key-derived exponent (p-1-x) with no check that it lies in the valid range, so a peer could submit a small-order or out-of-range element and, given a chosen-ciphertext decryption oracle against a reused decryption key, mount a small-subgroup confinement and key-recovery attack - weaker even than DHBasicAgreement, which already range-checks its peer value. processBlock now rejects gamma or phi outside [2, p-2] with an IllegalArgumentException ("ElGamal ciphertext element is weak") before the modular exponentiation, mirroring the validation added to DHAgreement. Legitimate ciphertexts are unaffected, a well-formed gamma always lying in (1, p-1), and the encryption path is unchanged.
- EthereumIESEngine, a standalone copy of IESEngine carrying the Ethereum RLPx tweaks and so not a subclass inheriting the fix above, had the same stream-mode key-derivation flaw: in the static-key path it placed the keystream K1 first and the MAC key K2 at a message-length-dependent offset behind it, so a single known-plaintext recovery of K1 exposed the MAC key of any shorter message and let an attacker forge a ciphertext and tag from one observation. It now uses the same fixed K2-first layout whether or not an ephemeral component is present, the keystream still being hashed into the MAC key with SHA-256. The ephemeral-component wire format is unchanged; only the static-static stream-mode encoding changes. As with IESEngine, static-key stream mode remains a deterministic many-time pad unsuitable for more than one message under a given key pair, as the javadoc now notes.
- PKIXCertPathReviewer.getPolicyTree() always returned null, even after successfully validating a certificate path whose certificates carry the certificatePolicies extension. The RFC 3280 sec. 6.1 policy processing in checkPolicy() built the valid policy tree in a local variable and discarded it at the end without ever assigning it to the policyTree field the getter returns (the field was left at the null set in init()), contradicting the method's documented contract and diverging from the JDK CertPathValidator, whose PKIXCertPathValidatorResult.getPolicyTree() exposes the tree for such a path. Both reviewer copies (org.bouncycastle.pkix.jcajce and org.bouncycastle.x509) now store the computed tree to the policyTree field, so getPolicyTree() returns the populated valid-policy-tree on a successful validation (and null only when no valid policy tree exists, as documented).
- The keybox (GnuPG .kbx) X509 certificate-blob parser (CertificateBlob.parseContent) read the u32 sizeOfReservedSpace length field and handed it straight to KeyBoxByteBuffer.bN, omitting the explicit "sizeOfReservedSpace exceeds content remaining in buffer" bounds check that its near-identical sibling PublicKeyRingBlob.parseContent already applies -- the guard had been added to one copy of the duplicated parse routine but not the other. A crafted keybox declaring an oversized reserved-space length therefore failed deep inside bN with a generic message rather than the descriptive IllegalStateException the OpenPGP blob raises. KeyBoxByteBuffer.bN's own size\<0 / size\>remaining guards already prevented an oversized allocation, so this completes the bounds check across the CertificateBlob / PublicKeyRingBlob pair for parser-robustness parity.
- KeyBoxByteBuffer.u32(), the keybox (GnuPG .kbx) parser's unsigned-32 reader, assembled the four bytes in int arithmetic and then widened to long, so a field with bit 31 set was sign-extended to a negative value - 0xFFFFFFFF read as -1 rather than 4294967295. That gave length, offset and size fields incorrect values above 2^31, silently defeated the "\> remaining()" length guards in the two blob parsers for the upper half of the u32 range (an oversized length slipped past the guard down to bN, which still rejected it, so no over-allocation occurred), and made the blob timestamp accessors return negative for dates beyond 2038. u32() now masks the assembled value to its unsigned range, so the guards cover the whole range and the timestamps stay positive. Values below 2^31, which is every keybox seen in practice, are unchanged.
- The keybox (GnuPG .kbx) key-blob parsers (CertificateBlob.parseContent and PublicKeyRingBlob.parseContent) read a u16 user-ID count and, for each entry, copied a slice of attacker-controlled length out of the blob. Each slice was bounded by the buffer size individually but not collectively, so a crafted blob declaring up to 65535 entries that each point at almost the whole blob could force retention of roughly bufferSize^2 bytes - a 150 KiB keybox driving multi-gigabyte allocation, reachable on untrusted input since the blob integrity digest is an unkeyed checksum an attacker can recompute. The cumulative user-ID data is now bounded by the blob's declared length, which a well-formed keybox always satisfies, and the parse aborts with an IllegalStateException ("userID data exceeds blob length") once the total exceeds it.
- MessageDigestUtils.getDigestName (org.bouncycastle.jcajce.util) mapped the RIPEMD-256 digest OID (TeleTrusTObjectIdentifiers.ripemd256, 1.3.36.3.2.3) to the name "RIPEMD-128" instead of "RIPEMD-256", a copy/paste error in the static OID table dating to 2015. Because getDigestName feeds digest creation in the operator layer (OperatorHelper.createMessageDigest), a certificate, CMS SignerInfo or OCSP response whose digest algorithm was RIPEMD-256 was either hashed with the 16-byte RIPEMD-128 digest (wrong digest, so signature verification false-rejects) or refused outright with NoSuchAlgorithmException, depending on whether the calling path stripped the hyphen from the returned name. The OID now maps to "RIPEMD-256"; the sibling JcaJceUtils.getDigestAlgName table was already correct. Every consequence was fail-closed (no false-accept).
- The OpenSSL key readers (org.bouncycastle.openssl) leaked unchecked exceptions out of parse methods that declare only IOException, the same class as the X509CertificateHolder and PKCS#12 hardening above. PEMParser's PublicKeyParser passed a malformed "PUBLIC KEY" body straight to SubjectPublicKeyInfo.getInstance with no try/catch, so a body decoding to the wrong ASN.1 type leaked out of readObject() where every other per-type parser wraps its decode in a PEMException; its KeyPairParser decoded a legacy DEK-Info IV with Hex.decode, which throws a DecoderException - a RuntimeException that is not an IllegalArgumentException - on a non-hex IV, past a catch handling only IOException and IllegalArgumentException; and JcaPrivateKeyReader.readDER guarded the outer DER shape but called the inner getInstance methods unwrapped. All three now wrap the decode and re-throw a PEMException.
- PKCS12KeyStoreSpi.engineLoad and PKCS12PBMAC1KeyStoreSpi.engineLoad leaked a RuntimeException out of their declared IOException contract when handed a malformed keystore. The top-level safe-contents parse loop was already guarded, but the MAC-data block sitting outside it was not: a corrupted MAC iteration count surfaced as IllegalStateException from PKCS12Util.validateIterationCount, and a MAC whose authenticated-safe content was not an OCTET STRING as IllegalArgumentException from PKCS12Util.getContentOctets, both reachable when loading an untrusted .p12. The MAC-parameter parse is now performed under the same guard as the MAC computation, so a malformed keystore fails with an IOException carrying the original cause; the intentional NullPointerException for a missing password is unchanged. Found by mutational fuzzing of KeyStore.load.
- CMSSignedData's parsing constructors (the byte[], InputStream and ContentInfo forms, and the shared CMSUtils.readContentInfo used by the other CMS container types) leaked a RuntimeException out of their declared CMSException contract on malformed input: an inner tag of the wrong class surfaced as IllegalStateException ("Expected CONTEXT tag but found APPLICATION", "unexpected implicit primitive encoding") from the ASN.1 layer, which the readContentInfo and CMSSignedData.getSignedData catch blocks (catching only IOException, ClassCastException and IllegalArgumentException) let through. Both catch sites now catch RuntimeException and re-throw it as CMSException ("Malformed content.", original cause attached), matching the declared contract and the CMSAuthEnvelopedData hardening of github #2133. Found by mutational fuzzing of the CMSSignedData(byte[]) constructor.
- The X509CRLHolder(byte[]) and X509CRLHolder(InputStream) constructors, which declare throws IOException, could instead leak an unchecked IllegalArgumentException on a malformed CRL. To decide whether a CRL is indirect, construction eagerly parses the issuingDistributionPoint extension value, and a structurally valid CertificateList carrying a non-DER extnValue there made that decode throw ("can't convert extension: ...") past the declared contract, so a caller catching only IOException crashed on a hostile CRL. The eager parse is now guarded and a malformed extension reported as a CertIOException; the X509CRLHolder(CertificateList) constructor, handed an already-parsed structure, continues to surface it as the unchecked exception it always has. X509CertificateHolder did not share this leak, as it does not eagerly parse an extension value.
- The PKCS#12 password-based key derivation in the pkix operator and OpenSSL PKCS#8 layer ran with an unbounded, wire-supplied iteration count, where the keystore path and the sibling PBES2 / scrypt / PBMAC1 paths already capped it. The count is carried in the PKCS12PBEParams of an attacker-supplied AlgorithmIdentifier and was fed straight into the KDF by five code paths across org.bouncycastle.pkcs.bc, .pkcs.jcajce and .openssl.jcajce. Decrypting an attacker-supplied encrypted PKCS#8 key or PKCS#12 bag, or verifying a PKCS#12 integrity MAC - where the MAC key is derived before the MAC can be checked, so the cost is pre-authentication - ran the derivation for as long as the count demanded, roughly 30 minutes of CPU at the 2^31-1 ceiling. The lightweight and JCE MAC paths now bound it through PKCS12Util.validateIterationCount (default 5,000,000) and the decryptor builders with the same org.bouncycastle.pbe.max_iteration_count check their PBES2 branch already used; the lightweight path previously truncated an oversized count with intValue(), silently producing a weak zero-round derivation.
- TimeStampResp and TimeStampReq (org.bouncycastle.asn1.tsp), the RFC 3161 response and request types, leaked an unchecked RuntimeException on a malformed top-level SEQUENCE instead of the IllegalArgumentException their getInstance contract implies: TimeStampResp read its mandatory status field through Enumeration.nextElement() with no hasMoreElements() guard, so an empty SEQUENCE threw NoSuchElementException, and TimeStampReq read its two mandatory leading fields by index with no check that the sequence held them. Both are reached from the public TimeStampResponse and TimeStampRequest entry points - the standard way a client parses a TSA reply or a server ingests a request - whose catch blocks are narrowed to IllegalArgumentException and ClassCastException, so the escaping exception violated their declared contracts. Both private constructors now reject a too-short SEQUENCE up front.
- During attribute-certificate path validation (PKIXAttrCertPathValidatorSpi, the "RFC3281" CertPathValidator), the attribute certificate's own signature was never cryptographically verified - RFC3281CertPathUtilities checked validity period, issuer, extensions and the issuer's certificate path, but not the signature over the AC itself, so a validation could succeed for an attribute certificate whose content had been tampered with or that was never signed by the named AC issuer. RFC3281CertPathUtilities now verifies the attribute certificate's signature against the AC issuer's public key (via the new CertPathValidatorUtilities.verifyX509AttributeCertificate, honouring the configured signature provider) and fails validation with a CertPathValidatorException when it does not verify.
- The NTRU+ KEM could fail decapsulation intermittently: a multiply-add step in the polynomial arithmetic used an unreduced value where R mod q was required, so for some (valid) key/ciphertext pairs the recovered shared secret disagreed with the encapsulated one. The reduction has been corrected and decapsulation now round-trips for all generated keys.
- org.bouncycastle.crypto.agreement.DHAgreement.calculateAgreement did not validate the peer's ephemeral public value ("message") before raising it to the local private key, allowing a peer to submit a small-order or out-of-range element (a small-subgroup confinement attack, which with a reused private key can leak it via CRT). The ephemeral value is now subjected to the same DH public-value range and subgroup checks as the peer's static key, and null arguments are rejected up front.
- Provider exception throws of UnrecoverableKeyException, IllegalBlockSizeException and BadPaddingException - JCA/JCE exception classes with no (String, Throwable) constructor - discarded the underlying cause, leaving only its message text folded into the new exception's string. Throw sites across the keystore SPIs and the KEM/cipher SPIs now attach the original exception as the cause (via the new org.bouncycastle.jcajce.provider.util.SecurityExceptions factories, which use initCause), so callers can walk getCause() for diagnosis; exception types and message texts are unchanged (issue #2309).
- A batch of fixed-arity ASN.1 SEQUENCE types leaked ArrayIndexOutOfBoundsException from getInstance(...) when handed a SEQUENCE with fewer elements than the type's mandatory minimum, instead of the IllegalArgumentException the contract implies. Lower-bound size checks with diagnosable "bad sequence size" messages were added to the decode constructors of the OCSP types RevokedInfo, SingleResponse, Signature, ResponseBytes and CertID, the CMS types Attribute, CompressedData, DigestedData, KeyTransRecipientInfo, OtherRevocationInfoFormat, RecipientEncryptedKey, OtherRecipientInfo, IssuerAndSerialNumber and OriginatorPublicKey, the CMP/CRMF types CertStatus, PBMParameter, CAKeyUpdAnnContent, PKMACValue, CertId, ProtectedPart, AttributeTypeAndValue and POPOSigningKeyInput, and PbkdMacIntegrityCheck. This complements the OtherName / SafeBag / SignerInfo hardening elsewhere in this release.
- The DSTU4145 Signature implementation threw a NullPointerException from initSign when handed a private key it did not recognise; it now fails with an InvalidKeyException identifying the problem, matching the initVerify path.
- Parsing an OpenPGP secret-key packet whose string-to-key usage octet named an unknown inner S2K type surfaced an unchecked UnsupportedPacketVersionException from SecretKeyPacket; it is now reported as a MalformedPacketException (an IOException subclass), so stream-parsing callers catching IOException see a malformed packet rather than an unchecked crash.
- The CRMF OptionalValidity type (org.bouncycastle.asn1.crmf) accepted an empty SEQUENCE on decode even though RFC 4211 requires at least one of notBefore/notAfter to be present - a rule its programmatic constructor already enforced. getInstance of an empty OptionalValidity now throws an IllegalArgumentException.
- A TLS server or client certificate carrying a malformed tls-features (RFC 7633) extension - one whose extension value is not a SEQUENCE - caused a ClassCastException during the BC TLS handshake. The malformed extension is now rejected with a fatal bad_certificate alert per the TLS protocol.
- DeltaCertificateRequestAttributeValue.getInstance (org.bouncycastle.asn1.x509) returned null for every input, making the delta-certificate-request attribute unreadable through the standard factory; it now decodes the attribute value properly, and an empty DeltaCertificateRequest SEQUENCE is rejected with a diagnosable IllegalArgumentException rather than an ArrayIndexOutOfBoundsException.
- DANEEntry.isValidCertificate (org.bouncycastle.cert.dane) contained an always-true logical-OR test, so entries with any certificate-usage octet were accepted; the check now enforces the RFC 6698/8162 certificate-usage range 0..3.
- TimeStampToken (org.bouncycastle.tsp) leaked ArrayIndexOutOfBoundsException for a token whose ESS signing-certificate attribute carried an empty certs SEQUENCE or an empty attribute-value SET, and ERSEvidenceRecord (org.bouncycastle.tsp.ers) did the same for an empty ArchiveTimeStampSequence or an empty chain; all four cases now fail with a diagnosable TSPException / ERSException, matching the classes' declared contracts.
- SSHBuffer (org.bouncycastle.crypto.util), used by the OpenSSH key parsers, treated a length prefix with bit 31 set as a large positive value, producing confusing failures downstream; block and big-num reads now reject a negative uint32 length prefix up front with a diagnosable exception.
- Parsing a malformed HTTP authentication challenge in an EST response (org.bouncycastle.est) could throw a StringIndexOutOfBoundsException from the challenge splitter; the parser now handles truncated and delimiter-less challenges and reports them cleanly.
- On the CMS AuthEnvelopedData generate side the content-encryption AlgorithmParameters were instantiated from the AES base-cipher name rather than the content-encryption OID, so AES-GCM content emitted a bare IV OCTET STRING where RFC 5084 requires GCMParameters (the CCM and ChaCha20-Poly1305 paths were similarly name-driven). The org.bouncycastle.cms.jcajce layer now resolves the parameters by OID, producing the RFC 5084 GCMParameters / CCMParameters encodings; the decode side already accepted both forms, so interop with BC's own earlier output is preserved.

### 2.4.3 Additional Features and Functionality

- KCCMBlockCipher (DSTU 7624 CCM mode) now accepts associated data whose length is not a multiple of the underlying block size and a nonce shorter than the block size, instead of throwing "padding not supported" or mis-constructing the MAC. init() zero-extends a short nonce to the block size, and processAssociatedText zero-pads the trailing partial associated-data block into the CBC-MAC. Multi-block associated data whose length is a multiple of the block size (the only variable-length case the previous code accepted) authenticates exactly as before (github PR #2350).
- As announced in the 1.84 release notes, the JCE wrappers for the pre-standardisation round-3 algorithms Dilithium, SPHINCS+ and Kyber have been removed: the BC provider no longer registers the "Dilithium" and "SPHINCSPlus" algorithm families or the SubjectPublicKeyInfo/PrivateKeyInfo key-info converters for their OIDs, and the BCPQC provider no longer registers "Dilithium", "SPHINCSPlus" or "Kyber" (which was just ML-KEM). The algorithm implementations themselves have not been deleted and remain accessible via the low-level org.bouncycastle.pqc.crypto APIs; they will be deleted in a later release. Applications should move to the standardised forms - ML-DSA, SLH-DSA and ML-KEM.
- The constants class org.bouncycastle.iana.AEADAlgorithm has been removed. It was added for draft-zauner-tls-aes-ocb (which expired without adoption) and has never been referenced by any BC code; the IANA AEAD algorithm-number registry it mirrored is unrelated to the org.bouncycastle.asn1.iana OID classes, which are unaffected.
- The IANA OID class org.bouncycastle.asn1.iana.IANAObjectIdentifiers has moved from the bcutil module to bcprov: it now lives in the core source tree (published in the bcprov jar and exported by the org.bouncycastle.provider module), and the previously separate internal org.bouncycastle.internal.asn1.iana copy used by core/prov has been removed so there is a single definition. The public class name is unchanged, so class-path users are unaffected. A JPMS (module-path) consumer that read org.bouncycastle.asn1.iana solely through "requires org.bouncycastle.util" must now add "requires org.bouncycastle.provider" (bcutil already requires bcprov, so the module is present on the path); OSGi consumers see the package exported by the bcprov bundle rather than bcutil (issue #2176).
- The SP 800-208 XMSS / XMSS^MT parameter sets (SHA-256/192, SHAKE256/256, SHAKE256/192) are now usable through the JCA/JCE. New tree-digest selector constants on XMSSParameterSpec / XMSSMTParameterSpec and the corresponding named parameter-set constants let a KeyPairGenerator from the BCPQC provider generate these sets, which previously could only be built through the lightweight API; the keys encode in the RFC 9802 form and round-trip through the BCPQC KeyFactory, and getTreeDigest() now accounts for the security parameter n, so SHA-256/192 is distinguished from SHA-256/256 and SHAKE256/192 from SHAKE256/256, which share a tree-digest OID. The lightweight XMSSParameters / XMSSMTParameters constructors taking an explicit n are now public, and an unknown tree digest fails with InvalidAlgorithmParameterException rather than a later NullPointerException (issue #2176).
- The tree-digest-named XMSS / XMSS^MT Signature algorithms from the BCPQC provider (XMSS-SHA256, XMSS-SHAKE256, XMSSMT-SHA256 and so on, with their proprietary OID aliases) now reject a key whose tree hash function does not match the named family, throwing InvalidKeyException from initSign / initVerify rather than silently signing or verifying with the key's own tree digest. The SP 800-208 SHAKE256/256 and SHAKE256/192 sets count as part of the SHAKE256 family, sharing the id-shake256-len tree-digest OID, and SHA-256/192 as part of SHA-256. The generic "XMSS" / "XMSSMT" signers remain key-driven and accept any key, and the "\<digest\>withXMSS-..." pre-hash signers are unaffected, their leading digest naming the message pre-hash rather than the key's tree digest (issue #2176).
- ARIA-GCM/CCM and SM4-GCM/CCM can now be used as CMS content-encryption algorithms for AuthEnvelopedData. Previously only AES-GCM/CCM and ChaCha20-Poly1305 were recognised as AEAD on the generate side, ARIA had no OID-addressable AEAD AlgorithmParameters and SM4 had no GCM/CCM Cipher at all, so a round trip under any of these failed. The BC provider now registers OID-addressable SM4-GCM / SM4-CCM Ciphers, AlgorithmParameters and AlgorithmParameterGenerators, and ARIA-GCM/CCM AlgorithmParameters and generators; the CMS encrypt path recognises all eight OIDs as AEAD and generates the correct RFC 5084 nonce and parameters for them; and the lightweight CipherFactory, CipherKeyGeneratorFactory and AlgorithmIdentifierFactory recognise them too, so both the JCE and lightweight content-encryptor builders can produce and recover such messages. Decode-side recognition was added in the same release.
- CMS recipients can now be restricted to a set of acceptable content-encryption algorithms. The new fluent setAllowedContentAlgorithms(Set\<ASN1ObjectIdentifier\>) is available on all five JCA/JCE recipients and on BcKeyTransRecipient, BcKEKRecipient and BcPasswordRecipient; when set, an attempt to recover content protected under any other content-encryption - or, for AuthenticatedData, content-MAC - algorithm is refused before any key unwrap or content processing, throwing the new CMSAlgorithmNotAllowedException, a subclass of CMSException so existing catch blocks are unaffected. This lets a caller reject an attacker downgrading the content-encryption algorithm carried in the recipient info. The shared state and check live on a new common base class, org.bouncycastle.cms.AbstractRecipient; with no allowed set configured every algorithm is accepted, as before.
- CMS recipients can now require a minimum AEAD authentication tag size when recovering AuthEnvelopedData. The new fluent setter setMinimumTagSize(int tagSizeInBits) is available on the JCA/JCE recipients (JceKeyTransRecipient, JceKeyAgreeRecipient, JceKEMRecipient, JcePasswordRecipient, JceKEKRecipient); when set, recovering content whose AES-GCM/CCM content-encryption algorithm carries a shorter ICV tag is refused before any decryption, throwing the new org.bouncycastle.cms.CMSTagLengthException (a subclass of CMSException). This is a caller-chosen floor layered on top of the existing global org.bouncycastle.gcm.allow_short_tags policy, letting a recipient reject an attacker downgrading the tag length (e.g. to 32 or 64 bits). The check (on org.bouncycastle.cms.AbstractRecipient) is a no-op for non-AEAD content and when no minimum is set, so default behaviour is unchanged.
- CMSSignedData.replaceSigners() and addDigestAlgorithm() recompute the SignedData version from the content per RFC 5652 (a non-id-data eContentType, for example, computes to version 3). A producer that needs to pin a specific version can now call the new CMSSignedData.asVersion(int), which returns a copy of the message with the SignedData version field forced to the given value and everything else unchanged. This covers interop with profiles that require a fixed version irrespective of content - notably Microsoft Authenticode, whose signatures must carry version 1 even though their SPC_INDIRECT_DATA eContentType would otherwise compute to version 3. The org.bouncycastle.asn1.cms.SignedData structure gains a constructor taking an explicit ASN1Integer version to support this (issue #2344).
- The Argon2 password-based KDF (RFC 9106) is now available through the BC JCE provider as SecretKeyFactory "ARGON2", complementing the existing lightweight org.bouncycastle.crypto.generators.Argon2BytesGenerator. Parameters are supplied via the new org.bouncycastle.jcajce.spec.Argon2KeySpec (variant Argon2d/Argon2i/Argon2id, version 1.0/1.3, salt, iterations, memory cost in KiB, parallelism and output key length in bits, plus optional secret and additional data), following the style of the existing SCRYPT SecretKeyFactory and ScryptKeySpec. The attacker-cost guards on the lightweight generator still apply: the memory exponent is capped by org.bouncycastle.argon2.max_memory_exp (default 24, i.e. 16 GiB).
- The BCJSSE hostname verifier no longer falls back to matching the subject CN of a server certificate when the certificate carries no SubjectAltName dNSName entry; by default only a matching SAN dNSName, or for an IP literal an iPAddress SAN, satisfies HTTPS endpoint identification. RFC 9525 sec. 6.3 deprecates CN as a TLS server identifier and CAB Forum Baseline Requirements 7.1.4.2 require SAN dNSName entries for publicly-trusted server certificates; the CN fallback was also a name-constraints bypass surface, since RFC 5280 constraints only constrain SubjectAltName entries of the constrained type, so a dNSName-constrained sub-CA could issue a SAN-less leaf carrying an unrelated hostname in CN. The legacy SunJSSE-compatible matching remains available as an opt-in through Properties.JSSE_HOSTNAME_CHECK_CN_FALLBACK.
- PKIXNameConstraintValidator gains an opt-in relaxed directoryName matching mode for GSMA SGP.22 v2.5 (Remote SIM Provisioning) certificate chains, gated behind the new org.bouncycastle.x509.sgp22_name_constraints property, default off. When enabled, a permitted-subtree RDN is satisfied by any matching subject RDN regardless of position, additional subject attributes beyond those named in the subtree are tolerated (SGP.22 sec. 4.5.2.1.0.2), and a serialNumber RDN is matched with startsWith wherever it appears (sec. 4.5.2.1.0.3) - deliberately looser than the contiguous-prefix DN matching RFC 5280 sec. 7.1 mandates. A pre-existing, ungated SGP.22 serialNumber startsWith concession in the strict path has been moved behind the same property, so default validation is now fully RFC 5280 strict (issue #2327).
- Classic McEliece as standardised in ISO/IEC 18033-2:2006/Amd 2:2026 (Clause 13) is now implemented under org.bouncycastle.crypto and registered in the BC provider, in the same style as ML-KEM and FrodoKEM. The standard selects sixteen parameter sets - the four code sizes mceliece460896, mceliece6688128, mceliece6960119 and mceliece8192128, each in a base form, a semi-systematic ("f") variant, a plaintext-confirmation ("pc") variant and a combined "pcf" variant - under id-kem-cm (1.0.18033.2.2.6.1 through .16). In a pc set the encapsulation appends a 32-byte confirmation C1 = Hash(2, e) and derives the session key over the full C0 || C1, the decapsulator recomputing and constant-time comparing C1 before implicit rejection; the non-pc and "f" sets are the existing NIST round-3 construction. All sixteen are available as crypto.params.CMCEParameters constants, driven by the lightweight generator, KEM generator and extractor, and through the BC provider as KeyPairGenerator / KeyFactory / KeyGenerator / Cipher "CMCE". All are verified byte-for-byte against the reference KAT vectors, the pc/pcf sets against vectors generated from the official libmceliece reference. The non-standardised mceliece348864 size is not provided here, and the earlier org.bouncycastle.pqc.crypto.cmce implementation is retained but deprecated.
- FrodoKEM as standardised in ISO/IEC 18033-2:2006/Amd 2:2026 (Clause 14) is now implemented under org.bouncycastle.crypto and registered in the BC provider, in the same style as ML-KEM. The standard specifies eight parameter sets at the 976 and 1344 security levels - the salted "FrodoKEM", applying the Salted Fujisaki-Okamoto transform so that a salt is folded into the G_2 hash and the derived shared secret and carried in the ciphertext, and the unsalted ephemeral "eFrodoKEM", to be used only where fewer than 2^8 ciphertexts are produced per public key - each with AES or SHAKE generation of the matrix A. All eight are available as crypto.params.FrodoKEMParameters constants, driven by the lightweight generator, KEM generator and extractor, and through the BC provider as KeyPairGenerator / KeyFactory / KeyGenerator / Cipher "FRODOKEM" under the new OIDs 1.0.18033.2.2.7.1 through .8. The implementation is verified byte-for-byte against the FrodoKEM team's reference KAT vectors for all eight, and the matrix multiply uses an ikj-ordered, JIT auto-vectorisable form identical to the schoolbook product. The earlier org.bouncycastle.pqc.crypto.frodo implementation is retained but deprecated.
- The (BC)JSSE provider now honours TlsPeer.getHandshakeTimeoutMillis() for blocking SSLSockets, configured through the new org.bouncycastle.jsse.handshakeTimeoutMillis system property (default 0, meaning no timeout). The handshake timeout was previously respected only by the DTLS protocols; the blocking stream-TLS path relied on the socket's per-read SO_TIMEOUT, which aborts a fully stalled peer but cannot bound the total handshake time, so a peer dripping bytes slower than the handshake completes but faster than SO_TIMEOUT could hold it open indefinitely. When the property is set the socket now enforces a total wall-clock deadline across the complete handshake, throwing a TlsTimeoutException when it expires. The default is unchanged, and the deadline is not applied to the transport-agnostic TlsClientProtocol / TlsServerProtocol stream API, which has no timed-read primitive (issue #1666).
- The BC JCE provider now registers the Java 9+ standard signature algorithm names for ECDSA producing IEEE P1363 format (fixed-width r || s) output: NONEwithECDSAinP1363Format and SHA1/SHA224/SHA256/SHA384/SHA512withECDSAinP1363Format, plus the SHA3-224/256/384/512 equivalents. These map to the same engine as the existing PLAIN-ECDSA / CVC-ECDSA names and are registered with the EC key attributes, so Signature.getInstance(...) resolves them on the auto-provider-selection path - which is how the JDK's built-in XML signature support (org.jcp.xml.dsig.internal.dom.DOMSignatureMethod) obtains an ECDSA Signature, previously forcing callers onto a custom bridge provider (issue #751).
- PGPCompressedData.getDataStream(long limit) is a new opt-in overload that caps the number of decompressed bytes a caller may read from an OpenPGP compressed data packet, throwing a StreamOverflowException once the limit is exceeded. Because the packet carries no decompressed-length field the existing no-arg getDataStream() returns an unbounded stream, so a small ZIP/ZLIB/BZIP2 packet can expand into an arbitrarily large amount of data where a caller buffers the full output; the new overload lets callers processing untrusted input bound that expansion ahead of reading, mirroring the existing ZlibExpanderProvider(long) limit. The no-arg behaviour is unchanged. Note the limit bounds decompressed output only - for BZIP2 the decompressor still allocates its fixed working buffers, sized by the packet's block-size header, at stream construction.
- The SHA_Interleave function from RFC 2945 sec. 3.1 (used by SRP-SHA1 to produce a 320 bit session key) is now available, as org.bouncycastle.crypto.digests.SHA1InterleaveDigest in the lightweight API and as MessageDigest "SHA1-INTERLEAVE" (alias "SHA-1-INTERLEAVE") in the BC JCE provider. The complete input is buffered until doFinal: leading zero bytes are removed, a further leading byte is removed if the remaining length is odd, the even-numbered and odd-numbered bytes are hashed separately with SHA-1, and the two hashes are interleaved to form the 40 byte result (issue #473).
- CMSEnvelopedDataStreamGenerator and CMSAuthEnvelopedDataStreamGenerator can now produce definite-length (DL) and DER encoded output for content of any size: setEncoding("DER"/"DL") plus the new open(out, inputLength, encryptor) overloads pre-compute every enclosing header from the content length, so nothing is buffered and the content may exceed the size of a Java array. The exact ciphertext length comes from the new KnownLengthOutputEncryptor interface where the encryptor implements it, falling back to an algorithm-identifier computation for CBC, AES-GCM and AES-CCM; both the declared content length and the predicted ciphertext length are enforced. For AuthEnvelopedData the AEAD tag lives in the separate mac field and any authenticated attributes are fed to the encryptor's AAD stream at open() time, ahead of the content. CMSSignedDataStreamGenerator gains the same for encapsulated content through new single-pass open(out, contentLength) overloads, which require the signer to implement the new FixedLengthContentSigner interface - supplied for RSA, Ed25519/Ed448 and ML-DSA, while variable-length DER ECDSA and DSA signatures are rejected up front with a pointer at the two-pass generate(out, CMSTypedData), which supports every algorithm by computing signatures in a first pass and re-digesting the re-read content in the second. Underpinning this are the new DLSequenceGenerator and DLOctetStringGenerator, and on the read side ASN1StreamParser now traverses definite lengths beyond 31 bits, so the CMS parsers round-trip such structures in full (issue #1482).
- PKIXCertPathReviewer now reports a notification when a non-CA certificate in the path carries the name constraints extension. RFC 5280 sec. 4.2.1.10 requires the extension to be used only in CA certificates, and the sec. 6.1 path validation algorithm never processes it on the final certificate, so its presence on an end-entity certificate is an issuance defect; behaviour elsewhere in the ecosystem is split (the JDK and OpenSSL accept such paths, GnuTLS/botan/wolfSSL reject them). BC's CertPathValidator is unchanged - it continues to accept the path, matching the JDK and OpenSSL - but both reviewer copies (org.bouncycastle.pkix.jcajce and org.bouncycastle.x509) surface the defect against the offending certificate (issue #2320).
- The JCA-backed TLS crypto (JcaTlsCrypto) now supports raw public key certificates (RFC 7250), reaching parity with the lightweight BcTlsCrypto; previously JcaTlsCrypto.createCertificate threw an unsupported_certificate alert for CertificateType.RawPublicKey. The new org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRawKeyCertificate wraps a SubjectPublicKeyInfo (reconstructing the java.security.PublicKey via the configured JcaJceHelper) and is now the base class for JcaTlsCertificate, mirroring the BcTlsCertificate extends BcTlsRawKeyCertificate structure so the signature/verifier handling is shared between the X.509 and raw public key cases. Raw public key handshakes (negotiated via the client_certificate_type / server_certificate_type extensions) now work end-to-end on either crypto backend.
- The NTRU KEM polynomial multiply (Polynomial.rqMul, the cyclic convolution in Z[x]/(x^n - 1) underlying key generation, encapsulation and decapsulation for every HPS / HRSS parameter set) has been reimplemented from a naive O(n^2) schoolbook convolution to recursive Karatsuba, O(n^1.585). Because the ring uses a power-of-two coefficient modulus and the multiply defers reduction to its caller, the kernel is closed under +/-/\* and the Karatsuba result is bit-for-bit identical to the schoolbook result modulo 2^16; the change is verified byte-identical against all KAT vectors and preserves the constant-time access pattern. End-to-end keygen, encapsulate and decapsulate is roughly 1.7x to 2.6x faster across the six parameter sets.
- GOST3412_2015Engine (Kuznyechik, GOST 34.12-2015 / RFC 7801) has been substantially sped up. The linear transform L - previously the LFSR R applied 16 times, some 256 GF(2^8) table lookups plus 16 register shifts per call - is now a set of precomputed lookup tables with the S-box folded into them, so each round is a key XOR plus one table pass, and the inverse round uses the equivalent-decryption restructure. The block-processing loop and the inverse step no longer allocate per-round work buffers, and the 64 KB GF(2^8) multiply table is no longer rebuilt per engine instance. Output is byte-identical and the change is constant-time-neutral, the tables being indexed by the same block bytes the S-box already indexes; measured around 9x faster on a CPU-bound encrypt and decrypt loop.
- TlsServer.getExternalPSK(Vector) now declares throws IOException, so a TLS 1.3 server can abort external-PSK selection with a specific alert by throwing a TlsFatalAlert from it - e.g. unknown_psk_identity when none of the offered identities is recognised, or decrypt_error when an identity is recognised but invalid or expired (RFC 8446 6.2). Previously the method could not signal an alert. The change is source- and binary-compatible for existing implementations (an override need not declare the exception); the default AbstractTlsServer implementation still simply returns null (issue #1673).
- AES-GMAC is now supported as the macAlgorithm in CMS AuthenticatedData per RFC 9044. The BC JCE provider registers Mac, KeyGenerator, AlgorithmParameters and AlgorithmParameterGenerator services for id-aes128-GMAC (2.16.840.1.101.3.4.1.9), id-aes192-GMAC (.29) and id-aes256-GMAC (.49), so JceCMSMacCalculatorBuilder(CMSAlgorithm.AES128_GMAC) (and the 192/256 variants) produces and verifies an AuthenticatedData whose macAlgorithm carries the RFC 9044 GMACParameters (a 12-octet nonce and, by default, a 16-octet tag). GMACParameters shares the RFC 5084 GCMParameters wire format, so the parameter handling is aliased to the existing GCM AlgorithmParameters; org.bouncycastle.crypto.macs.GMac.init now also accepts AEADParameters so the RFC 9044 tag length (12 to 16 octets) flows through to the computed MAC.
- The system/security property "org.bouncycastle.gcm.allow_short_tags" (Properties.GCM_ALLOW_SHORT_TAGS) lets callers opt in to short AES-GCM authentication tags. RFC 5084 constrains the GCMParameters ICV length to 12 to 16 octets, which BC enforces by default on both the read and write sides of CMS AuthEnvelopedData. With the property set, GCMParameters additionally accepts tags down to the NIST SP 800-38D minimum of 4 octets - sec. 5.2.1.2 permitting a 32-bit tag for limited applications - so a CMS AuthEnvelopedData carrying one can be produced and consumed. Short tags weaken integrity protection, so this defaults to off; anything below 4 or above 16 octets is still rejected, and with the property unset a sub-12-octet tag continues to be refused with "Invalid ICV length".
- KeccakDigest, and so every SHA-3, SHAKE, cSHAKE, KMAC, ParallelHash and TupleHash instance plus all SHAKE-based PQC schemes, now packs only the squeeze lanes a caller actually consumes. Each squeeze block previously converted the full rate - all 17 lanes, 136 bytes, for SHAKE256 - from the state into the internal byte queue even when the caller read fewer bytes; the packing is now deferred and materialised lazily per consumed lane. The change is byte-for-byte output-preserving, verified against the SHA-3 / SHAKE / cSHAKE / KMAC CAVP vectors and the ML-KEM / ML-DSA / SLH-DSA KATs including the SavableDigest encode-mid-squeeze round-trip, and noticeably speeds up consumers that squeeze less than a full rate block: roughly 1.11x for SLH-DSA-SHAKE signing and 1.12x for SHA3-256 of short inputs. Full-block consumers are unaffected.
- KCCMBlockCipher (DSTU 7624 CCM mode) now accepts input whose length is not a multiple of the underlying block size, where previously a partial block threw "partial blocks not supported". Partial blocks follow the generic CCM construction (NIST SP 800-38C / RFC 3610): the CBC-MAC zero-pads the trailing partial block and the counter keystream is truncated for it. DSTU 7624:2014 publishes no partial-block CCM test vector, so the behaviour is verified by round-trip self-consistency only, and callers needing guaranteed DSTU 7624 interoperability should keep input block-aligned. DSTU7624Mac, a CBC-MAC variant that binds no message length, deliberately continues to reject non-block-aligned input, since padding an unkeyed-length CBC-MAC would introduce tag collisions (issue #287).
- The four exception classes in org.bouncycastle.operator (OperatorException, OperatorCreationException, OperatorStreamException, RuntimeOperatorException) now carry class-level and per-constructor javadoc explaining what each exception represents and what its typical underlying causes are. The three classes that previously kept the cause in a private field and overrode getCause() (OperatorException, OperatorStreamException, RuntimeOperatorException) now route the cause through the standard Throwable(msg, cause) constructor so printStackTrace() prints "Caused by: ..." for the original failure (issue #1504).
- Initial CAdES (CMS Advanced Electronic Signatures) high-level builders, in the new org.bouncycastle.cades package, covering all four CAdES baseline levels (ETSI EN 319 122-1 / RFC 5126). B-B is CAdESSignerInfoGeneratorBuilder and CAdESSignedDataGenerator - the mandatory ESS signing-certificate-v2 reference plus optional commitment-type, signature-policy, signer-location and content-hints attributes. B-T is CAdESSignatureTimestampUtil, attaching a signature timestamp over the SignerInfo signature value from a caller-fetched RFC 3161 token. B-LT is CAdESLongTermValuesUtil, covering the certificate and revocation refs and values attributes for both CRLs and OCSP responses. B-LTA is CAdESArchiveTimestampUtil, an archiveTimestampV2 over the ETSI TS 101 733 v1.7.4 Annex A.2 canonicalisation with archive-timestamps stripped so chains are renewable. Each of the last three ships a read-back accessor and a self-consistency check that re-derives the covered imprint, and CAdESLevelDetector reports the level a SignerInformation attains. The EN 319 122-1 v3 archive-timestamp form is not yet supported (issue #275).
- The system/security property "org.bouncycastle.pkcs1.strict_digestinfo" (also exposed as Properties.PKCS1_STRICT_DIGESTINFO) lets callers opt in to strict RFC 8017 Appendix A.2.4 enforcement when verifying RSA PKCS#1 v1.5 signatures: when set to "true", DigestInfo encodings whose AlgorithmIdentifier omits the required NULL parameters octets are rejected. Default (unset / "false") preserves the legacy lenient fallback that accepts the two-byte-shorter encoding for compatibility with implementations that have historically produced it. Affects both the BC JCE provider's DigestSignatureSpi (e.g. Signature.getInstance("SHA256withRSA", "BC")) and the lightweight crypto RSADigestSigner (issue #2273).
- The system/security property "org.bouncycastle.asn1.allow_non_der_time" (Properties.ASN1_ALLOW_NON_DER_TIME) controls whether an ASN.1 UTCTime / GeneralizedTime carrying non-DER contents may be serialized through a DEROutputStream. Reading is always lenient: a wire value that is valid ASN.1 but not valid DER - a UTCTime without seconds, a time terminated with a "+hhmm" offset rather than "Z", a GeneralizedTime fraction with trailing zeros - parses without complaint. The default, "true", preserves BC's historical pass-through, allowing such a primitive to be re-emitted as DER unchanged; setting it to "false" enforces the DER restrictions of X.690 sec. 11.7 / 11.8 on the write side, toDERObject() throwing if it would emit non-conformant content. BER serialization is unaffected, and a time constructed from a Date always produces DER content (issue #1973 / #1986).
- KeyPurposeId constants for the four Extended Key Usage KeyPurposeIds defined in RFC 9809 sec. 3: id_kp_configSigning (id-kp 41, signing general-purpose configuration files), id_kp_trustAnchorConfigSigning (id-kp 42, signing trust anchor configuration files), id_kp_updatePackageSigning (id-kp 43, signing software / firmware update packages) and id_kp_safetyCommunication (id-kp 44, authenticating peers for safety-critical communication). The matching human-readable names are also registered in X509CertificateFormatter so the new EKUs print symbolically.
- KeyPurposeId constant for the Extended Key Usage KeyPurposeId defined in RFC 9734 sec. 3: id_kp_imUri (id-kp 40, 1.3.6.1.5.5.7.3.40), included in certificates that prove the identity of an Instant Messaging (IM) client whose IM URI (RFC 3860) or XMPP URI (RFC 6121) appears in the subjectAltName. The matching human-readable name is also registered in X509CertificateFormatter so the EKU prints symbolically.
- RFC 9763 ("Related Certificates for Use in Multiple Authentications within a Protocol") support, the non-composite path for hybrid post-quantum migration. Two new ASN.1 types: org.bouncycastle.asn1.x509.RelatedCertificate, the extension carried on the new-algorithm end-entity certificate under id-pe-relatedCert, holding a digest algorithm and a hash of the entire related Certificate DER; and org.bouncycastle.asn1.cms.RequesterCertificate, the CSR attribute value under id-aa-relatedCertRequest, carrying an IssuerAndSerialNumber, a requestTime, location URIs and a signature. A new BinaryTime implements the RFC 6019 seconds-since-epoch time requestTime uses. Operator-style helpers in the new org.bouncycastle.cert.RelatedCertificateTool, a sibling of DeltaCertificateTool, cover build and verify for both structures plus toAttribute / fromAttribute. Note writeSignatureInput streams the sec. 4.1 signed bytes - the bare concatenation of DER(certID) and DER(requestTime), not a SEQUENCE wrapper - straight into a supplied OutputStream.
- KeyPurposeId constant id_kp_documentSigning (id-kp 36) for the Extended Key Usage KeyPurposeId defined in RFC 9336 sec. 3.1, identifying public keys whose certified usage is to verify signatures over documents intended for human consumption (PDF, XML, JSON, etc.) — distinct from id_kp_codeSigning (executable code) and id_kp_emailProtection (S/MIME). The matching human-readable name is also registered in X509CertificateFormatter so the new EKU prints symbolically.
- FalconPrivateKeyParameters.getPublicKeyParameters() returns the matching FalconPublicKeyParameters for a private key, mirroring MLDSAPrivateKeyParameters.getPublicKeyParameters(). When the private key no longer carries its encoded public key (e.g. it was reconstructed from only the private encoding f ‖ g ‖ F, with no public key bytes or key-generation seed retained), the public key h is recomputed from the private polynomials as h = g \* f^-1 mod (q, x^n+1). Lets wallet / HSM code recover the public key from a stored private key without re-running keygen (issue #2297).
- The system/security property "org.bouncycastle.x509.crl_cache_ttl" (also exposed as Properties.X509_CRL_CACHE_TTL) sets a TTL, in seconds, for entries in the internal CRL cache used by CertPathValidator and X509RevocationChecker. When set to a positive value, cached entries are evicted whichever expires sooner: the configured TTL or the CRL's own nextUpdate. Unset (or 0) preserves the legacy behaviour of trusting the CRL's nextUpdate alone (issue #1833).
- The BC PKCS#12 KeyStore (types "PKCS12", "PKCS12-DEF" and variants, plus "PKCS12-PBMAC1") now accepts SecretKey entries through the standard JCE KeyStore.SecretKeyEntry API. Entries are written in the standards-compliant RFC 7292 sec. 4.2.5 secretBag form, the inner SecretBag carrying the algorithm OID as secretTypeId and the encoded key as a DER OCTET STRING, placed inside the keystore's encrypted SafeContents block so the raw bytes are protected by the keystore PBE. Phase 1 supports algorithms with a registered OID - AES, DESede and the HmacSHA1 / SHA-2 / SHA-3 families - anything else being rejected at setKeyEntry time with a pointer at BCFKS. As an opt-in interop path, Properties.PKCS12_ALLOW_SUN_SECRET_KEYS lets BC additionally decode SunJCE-style secretBag entries on load; BC always writes the standards-compliant form (issue #1807).
- The system/security properties "org.bouncycastle.argon2.max_memory_exp", "max_passes" and "max_parallelism" bound the Argon2 cost parameters accepted from untrusted input, notably an OpenPGP Argon2 S2K specifier whose passes, parallelism and memory fields are honoured before the message can be authenticated. max_memory_exp caps the memory exponent; its default has been lowered to 24 (16 GiB) from 30 (1 TiB) so that a single decrypt attempt cannot exhaust the heap, and it may still be raised to a ceiling of 30. max_passes (default 10) and max_parallelism (default 16) bound the iteration and lane counts, which OpenPGP key derivation previously accepted unbounded at one byte each; a passphrase-encrypted message exceeding any active limit is now rejected with a PGPException rather than processed.
- Argon2BytesGenerator now accepts a caller-supplied BlockPool via Argon2Parameters.Builder.withBlockPool(...), allowing reuse of working memory across successive generateBytes calls (issue #1646 / PR #1647). A bounded FixedBlockPool implementation is included.
- Argon2BytesGenerator's BLAKE2 compression (the dominant cost in fillMemoryBlocks) has been restructured so each of the eight G mixing functions per round loads its four working words into locals, mixes them entirely in registers, and writes them back once, instead of re-reading and re-writing the backing long[] on every quarter-round. The change is byte-identical (RFC 9106 / draft-irtf-cfrg-argon2 vectors unchanged) and touches only the data-independent compression, so the data-dependent (Argon2d/id) addressing and its constant-time posture are unaffected. Measured ~6-10% faster end-to-end across HotSpot (JDK 8-25) and GraalVM.
- BCFKS keystore now supports storing and retrieving javax.crypto.interfaces.PBEKey entries, so passwords and other PBE-based secrets no longer need to be stored as HMAC keys (issue #2164).
- X509v3CertificateBuilder now exposes setters for the constructor arguments (setIssuer, setSerialNumber, setNotBefore, setNotAfter, setSubject, setSubjectPublicKeyInfo) to support equivalence-comparison use cases (issue #1545).
- org.bouncycastle.asn1.x509.qualified.QcType — typed wrapper for the ETSI EN 319 412-5 sec. 4.2.3 QcType statementInfo (SEQUENCE OF OBJECT IDENTIFIER) carried inside a QCStatement whose statementId is id_etsi_qcs_QcType. Constructors take either a single OID or an array; hasType(ASN1ObjectIdentifier) returns whether a given QcType OID (id_etsi_qct_esign / id_etsi_qct_eseal / id_etsi_qct_web) is declared. QCStatementUnitTest has been extended to round-trip every ETSI QC statement type — QcCompliance, QcSSCD, QcType, QcCClegislation, RetentionPeriod and LimitValue — through encode/parse via QCStatement (issue #1467).
- CMSSignedDataParser now exposes getCertificateSet() and getCRLSet(), returning the raw ASN1Set fields as parsed from the wire and so preserving every certificate and CRL choice - X.509, attribute certificate, other-format - in original encoding order. The existing getCertificates() / getCRLs() Stores filter to X.509 only, which is enough for typical verification but loses non-X.509 choices and is unsuitable where the wire-encoding order matters, as in archive-timestamp imprint canonicalisation. Building on them, CAdESArchiveTimestampUtil.computeArchiveTimestampImprint now also accepts a CMSSignedDataParser, computing the ETSI TS 101 733 Annex A.2 archive-timestamp v2 imprint directly from the parser without materialising the whole SignedData (issue #1983).
- The CMS stream parsers now also expose the original wire coding of the remaining SignedData fields: CMSContentInfoParser.isBEREncoded() reports whether the outer ContentInfo used the indefinite-length method, getDigestAlgorithmsSet() returns the digestAlgorithms field as a BERSet or DLSet reflecting the wire form with original element order, and isContentBEREncoded() reports whether the eContent OCTET STRING was constructed or primitive definite-length - removing the need for a second raw pass when the original coding must be reproduced. For augmentation, replaceSignersPreservingEncoding() rewrites the signerInfos of a SignedData stream while copying the version, digestAlgorithms, encapContentInfo, certificates and crls through verbatim, the content piped rather than buffered, so everything an ETSI TS 101 733 archive-timestamp v2 imprint covers is preserved byte for byte (issue #1983).
- S/MIME boundary scan failures (a multipart missing its closing boundary line) now throw SMIMEBoundaryNotFoundException, a MessagingException subclass carrying typed diagnostics: the boundary, the body part's Content-Type/Content-Disposition, the expected and found boundary-line counts, and the bytes consumed from the raw stream - all of which also appear in the exception message. The last non-empty line read before the failure is available via getLastLineRead() only and is deliberately excluded from the message, so stack traces remain free of potentially confidential message content by default (issue #2318).
- The CMS generators now support encoding selection uniformly: setEncoding("BER"/"DL"/"DER") has been promoted to the CMSSignedGenerator and CMSEnvelopedGenerator base classes, so it is available on the signed, enveloped, auth-enveloped and authenticated data generators, in-memory and streaming alike, and is honoured through getEncoded(). In the definite-length modes the encrypted or encapsulated content is carried as a primitive OCTET STRING and the EnvelopedData / AuthEnvelopedData / AuthenticatedData / EncryptedContentInfo classes now follow their components, as SignedData already did, with "DER" producing a canonical encoding. The streaming generators need the content length supplied up front, and CMSAuthenticatedDataStreamGenerator has gained matching open() methods - the MAC algorithm must have a spec-fixed output length for the mac field to be sized before the content streams. The default remains BER and BER output is unchanged; note a parse of a fully definite-length message now re-encodes definite-length rather than being forced back to BER (issue #1296).
- CMS EnvelopedData now supports RFC 8418 ECDH key agreement using X25519 or X448 with HKDF (SHA-256/384/512). Three CMSAlgorithm constants (ECDH_HKDF_SHA256, ECDH_HKDF_SHA384, ECDH_HKDF_SHA512) and the corresponding KeyAgreement registrations (XDHwithSHA256HKDF / XDHwithSHA384HKDF / XDHwithSHA512HKDF) have been added (issue #1845).
- The SM2 JCE Cipher now accepts a ciphertext-format mode in the transformation string. Cipher.getInstance("SM2/C1C3C2/NoPadding", "BC") and Cipher.getInstance("SM2/C1C2C3/NoPadding", "BC") select between the two SM2Engine modes; the previous "SM2"/"SM2/NONE/NoPadding" forms continue to default to C1C2C3 (issue #1302).
- SimplePKIResponse now also accepts the unsigned Full PKI Response variant used for EST server-generated errors (RFC 7030 4.2.3 / 4.4.2): a CMS SignedData carrying an id-cct-PKIResponse PKIResponse SEQUENCE. New accessors getPKIResponse(), getControlAttributes(), getCmsContents() and getStatusInfoV2() return the embedded content as structured TaggedAttribute / TaggedContentInfo / CMCStatusInfoV2 objects. A new PKIResponseBuilder assembles SimplePKIResponse instances for both shapes — the Full PKI Response error case (addControlAttribute / addStatusInfoV2 / addCmsContent / addOtherMsg) and the cert-delivery success case used by EST /simpleenroll (addCertificate). CMSSignedData has a new getSignedContentType() returning the encapsulated content type as an ASN1ObjectIdentifier (issue #1452).
- org.bouncycastle.gpg.KeyGripCalculator computes the GnuPG-style 20-byte SHA-1 keygrip for a BCPGKey. The calculator is constructed with a caller-supplied SHA-1 PGPDigestCalculator. RSA public keys are supported initially (matching libgcrypt's \_gcry_rsa_compute_keygrip: SHA-1 of the canonical unsigned big-endian modulus); other key types throw on calculateKeygrip() until support is added (issue #676).
- CMS key transport now supports the SM2 cipher: JceKeyTransRecipientInfoGenerator wraps the CEK and JceKeyTransRecipient unwraps it when the keyEncryptionAlgorithm is GMObjectIdentifiers.sm2encrypt_with_sm3. The ciphertext format defaults to C1C3C2 (GB/T 35276 envelope encoding) and the SM4-CBC content encryption is exposed as the new CMSAlgorithm.SM4_CBC constant.
- org.bouncycastle.asn1.pkcs.SecretBag — RFC 7292 ASN.1 holder for the PKCS#12 secretBag bag type, complementing the existing CertBag / CRLBag classes. PKCS12SecretBag and PKCS12SecretBagBuilder in org.bouncycastle.pkcs sit alongside the SafeBag / SafeBagBuilder pair: PKCS12SafeBagBuilder takes a PKCS12SecretBag in a new constructor, and PKCS12SafeBag.getBagValue() returns a PKCS12SecretBag for safe bags of type secretBag.
- JCE provider plumbing for the LEA (Lightweight Encryption Algorithm) block cipher built on the existing core LEAEngine. Cipher.LEA (ECB) plus the standard transformation forms (LEA/CBC/PKCS5Padding etc.), Cipher.LEA-GCM, Cipher.LEA-CCM, Mac.LEA-CMAC / LEA-GMAC / LEA-Poly1305, KeyGenerator.LEA and SecretKeyFactory.LEA are registered, with 128/192/256-bit keys supported.
- org.bouncycastle.pkcs.util.PKCS12Util replaces org.bouncycastle.jce.PKCS12Util as the canonical helper for re-encoding PKCS#12 files to definite length. The new class additionally understands RFC 9579 PBMAC1-protected PFX files (the deprecated org.bouncycastle.jce.PKCS12Util threw UnsupportedOperationException for those). Existing org.bouncycastle.jce.PKCS12Util callers continue to work for the legacy SHA-based PBE MAC; the class is now annotated @Deprecated.
- HashMLDSASigner now exposes generateSignature(hash) and verifySignature(hash, signature) overloads alongside the streaming Signer API, letting callers feed an externally computed digest into HashML-DSA without having to stream the message through update(...). The DER-encoded digest OID is taken from the parameter set the signer was initialised with. The same external-hash mode is exposed through the BC JCE provider via Signature.getInstance("ML-DSA-{44,65,87}-WITH-SHA512-EXTERNAL-HASH", "BC") (plus the parameter-set-agnostic "HASH-ML-DSA-EXTERNAL-HASH"); Signature.update(...) accepts the pre-computed SHA-512 digest in place of the message, and a wrong-length input is reported as a SignatureException (issue #2198).
- BLS signatures over the BLS12-381 curve, per draft-irtf-cfrg-bls-signature, in the new org.bouncycastle.crypto.bls package. Public keys are 48-byte compressed G1 points and signatures 96-byte compressed G2 points in the Zcash encoding used by Eth2 consensus clients, Filecoin and Zcash. All three variants are provided as static-API classes - BLS12_381BasicScheme, BLS12_381MessageAugmentation and BLS12_381ProofOfPossession, the last with PopProve / PopVerify and a fastAggregateVerify path - each offering KeyGen, SkToPk, KeyValidate, Sign, Verify, Aggregate and AggregateVerify, with a BC-conventional BLSSigner / BLSKeyPairGenerator / BLSParameters surface alongside. Aggregate-verify enforces the draft sec. 2.9 per-message aggregated-key identity-rejection check on every path, blocking the rogue-key cancellation forgery in which an attacker holding pk and -pk submits an aggregate whose contributions cancel. Built on RFC 9380 hash-to-curve, the optimal ate pairing with a multi-pairing sharing one final exponentiation across N verifications, endomorphism-based subgroup checks and constant-time scalar multiplication; cross-checked byte-for-byte against the Eth2 bls12-381-tests vectors.
- XChaCha20 stream cipher and XChaCha20-Poly1305 AEAD per draft-irtf-cfrg-xchacha-03. The new lightweight XChaCha20Engine and XChaCha20Poly1305 take a 256 bit key and a 192 bit nonce: the first 128 bits of nonce plus the key feed HChaCha20 to derive a 256 bit subkey, which is then used with the remaining 64 bits of nonce, prefixed with four zero bytes to form a 96 bit IETF nonce, to drive a standard ChaCha20-IETF stream. The 192 bit nonce removes the per-key counter and deterministic-nonce constraint of standard ChaCha20-Poly1305 by making collisions negligibly likely up to around 2^80 random nonces per key. Registered in the BC provider as Cipher.XChaCha20 / Cipher.XChaCha20-Poly1305 with matching KeyGenerator and AlgorithmParameters entries; ChaCha20Poly1305's underlying engine and nonce size are now extension points, so the AEAD construction is reused unchanged (issue #631).
- BcPasswordRecipientInfoGenerator / JcePasswordRecipientInfoGenerator now reject AES_GCM, AES_WRAP and AES_WRAP_PAD as kekAlgorithm with a message that points the caller at RFC 3211 sec. 2.3 (PWRI-KEK requires a CBC-mode block cipher inner KEK, distinct from the AEAD or wrap algorithm used for the content encryption). The previous error "cannot find key size for algorithm: ..." was opaque. As a related broadening of legitimate PWRI-KEK support, the kek size lookup table and the BcCMS createRFC3211Wrapper factory now also recognise CAMELLIA{128,192,256}\_CBC, complementing the JCE-side CamelliaRFC3211Wrap registration (issue #491).
- SignerInformation now offers a three-argument addCounterSigners(SignerInformation outer, SignerId targetCounterSigner, SignerInformationStore counterSigners) overload that nests the supplied counter-signers underneath the counter-signer in `outer`'s subtree whose SID matches `targetCounterSigner`, rebuilding the containing SignerInfos on the way back up. The existing two-argument form remains unchanged and still attaches its counter-signers as peers of any existing counter-signers (an additional counterSignature attribute in `outer`'s unsignedAttributes, per RFC 5652 sec. 11.4) — callers who wanted to build a counter-counter-signature tree previously had no way to do so. Counter-signatures live in unsignedAttributes, which is not covered by the enclosing signer's signature, so the rewrite preserves all existing signatures (issue #769).
- RFC 9802 ("Use of the HSS and XMSS Hash-Based Signature Algorithms in Internet X.509 Public Key Infrastructure") support. The HSS/LMS leg was already in place; XMSS and XMSS^MT now follow: the new IANAObjectIdentifiers constants id_alg_xmss_hashsig (1.3.6.1.5.5.7.6.34) and id_alg_xmssmt_hashsig (.35) are used as the public key and signature AlgorithmIdentifier with parameters absent, the raw RFC 8391 public key carried directly in the BIT STRING with no OCTET STRING wrapping and the raw signature directly in the signatureValue. The key and signature factories, the BCPQC registrations, the BC-provider key-info converters and the signature name finders all produce and recognise the RFC form, while the draft-vangeest-x509-hash-sigs encoding and the original BC-proprietary parameterised form continue to be read, as do mixed variants of either. Decoding a SubjectPublicKeyInfo whose parameter-set identifier is unrecognised now fails with an IOException naming it rather than a NullPointerException, and the three self-signed example certificates from RFC 9802 Appendices A-C are carried as interop vectors (issue #2002).
- Support for the legacy pre-RFC 3161 Microsoft Authenticode time stamping protocol, the PKCS#9-countersignature-based protocol behind "signtool /t". The new ASN.1 class org.bouncycastle.asn1.microsoft.TimeStampRequest models the wire-format request - a countersignatureType OBJECT IDENTIFIER, optional Attributes, and a ContentInfo of type data carrying the signature to be countersigned - and MicrosoftObjectIdentifiers gains the countersignature type OID (1.3.6.1.4.1.311.3.2.1). The response is a plain PKCS#7 SignedData incorporated as a PKCS#9 countersignature, which the existing CMS API already covers; a self-contained end-to-end example ships in misc (issue #2005).
- The Gradle build now exposes a top-level `copyJars` task (in the `distribution` group) that gathers the produced jars (main, sources and javadoc) for `bccore`, `bcutil`, `bcprov`, `bcpkix`, `bcpg`, `bctls`, `bcmls`, `bcmail` and `bcjmail` into a single `dist/` directory at the project root, providing a "dist"-style aggregate output for consumers who don't want to scrape each module's `build/libs` directory. The directory is cleared at the start of each invocation so stale version artifacts don't accumulate. A sibling `copyMavenJars` task produces the same set minus `bccore`, matching the artifacts published to Maven Central (`bccore`'s classes are already bundled into `bcprov`) (issue #2301).
- PEMUtilities.crypt, used by JcePEMEncryptorBuilder / JcePEMDecryptorProviderBuilder for the OpenSSL legacy PEM private-key encryption form, now recognises the SM4- algorithm-name prefix alongside AES-, DES-, DES-EDE-, BF- and RC2-, so a key written with "DEK-Info: SM4-CBC,\<iv\>" can be parsed and decrypted through the normal PEMParser path instead of throwing "unknown encryption with private key". JcePEMEncryptorBuilder additionally chooses a 16-byte IV for SM4- algorithms, matching SM4's 128-bit block size, where previously the 8-byte default for the 64-bit-block legacy ciphers applied; key derivation follows the same OpenSSL EVP_BytesToKey path the AES- branch uses. Note this is the legacy OpenSSL PEM encryption format, distinct from the PKCS#5 PBES2 SM4-CBC support added under issue #1454 (issue #1066).
- JceOpenSSLPKCS8EncryptorBuilder and JceOpenSSLPKCS8DecryptorProviderBuilder, and the underlying PEMUtilities cipher and PRF tables, now support SM4-CBC as a PBES2 content-encryption algorithm and HMAC-SM3 as a PBKDF2 PRF, alongside the existing AES-CBC / 3DES-CBC ciphers and the SHA-1 / SHA-2 / SHA-3 / GOST3411 PRFs. PKCS8Generator and the encryptor builder expose the new SM4_CBC constant (GMObjectIdentifiers.sms4_cbc) and PKCS8Generator exposes PRF_HMACSM3, so a caller can produce a GM/T-aligned encrypted PKCS#8 in a single line. The provider's SM4 registration gained AlgorithmParameters and AlgorithmParameterGenerator OID aliases for sms4_cbc so the standard PKCS#8 / PBES2 lookup pipeline resolves correctly (issue #1454).
- A new convenience class org.bouncycastle.openssl.jcajce.JcaPrivateKeyReader reads a private key from a file, stream, byte[] or Reader and returns a java.security.PrivateKey, auto-detecting the encoding: PKCS#1 and PKCS#8 keys, in PEM or DER, including the password-protected variants, which are decrypted with a supplied password. PEM forms are dispatched by the type PEMParser returns and DER forms by the structure of the outermost SEQUENCE, with no element-count heuristics; a bare PKCS#1 RSAPrivateKey is wrapped as a PKCS#8 PrivateKeyInfo before conversion. The writers are unchanged and remain the way to emit keys. JcaPKIXIdentityBuilder now delegates its key parsing to the new reader and gains a setPassword(char[]) method, so it loads encrypted private keys where previously it failed with "unrecognised private key file". Based on initial work contributed in github #597.
- RFC 7894 "Alternative Challenge Password Attributes for Enrollment over Secure Transport (EST)" support. Three new PKCS#9 OIDs in the id-aa branch - id_aa_otpChallenge, id_aa_revocationChallenge and id_aa_estIdentityLinking - with matching typed value classes under org.bouncycastle.asn1.est. Each wraps a DirectoryString (SIZE 1..255), picking PrintableString when the input is in the printable subset and UTF8String otherwise as sec. 3 recommends, and exposes toAttribute() / fromAttribute() helpers; the existing CSRAttributesResponse indexer recognises the new OIDs automatically. ESTService.enrollPop and its siblings gain overloads accepting a CSRAttributesResponse, and a new TlsUniqueAttributeUtil centralises the sec. 4 selection rule: where the server advertises id-aa-estIdentityLinking the tls-unique value goes in that attribute, otherwise the legacy challengePassword attribute is used. Existing overloads are unchanged on the wire (issue #338).
- JceCMSContentEncryptorBuilder and BcCMSContentEncryptorBuilder now accept a caller-supplied content-encryption key through new build overloads - build(SecretKey) and build(byte[]) on the JCE side, build(byte[]) and build(KeyParameter) on the lightweight side. The original build() continues to draw a fresh key internally, which is correct for CMS EnvelopedData where the CEK is freshly drawn per message and wrapped per recipient; the new overloads support the EncryptedData case of no recipients and a long-lived locally-stored key, and the case where the CEK comes from an external KMS such as AWS Nitro Enclaves. The build(KeyParameter) form lets callers who already hold a BC KeyParameter feed it in without an intermediate byte[] round trip (issues #1509 / #2115).
- FAEST post-quantum digital signature scheme per the FAEST v2.0 algorithm specification (NIST PQC additional digital signatures process). Lightweight implementation in org.bouncycastle.pqc.crypto.faest covering all twelve parameter sets - base FAEST with the AES one-way function and FAEST-EM with the Even-Mansour one, each at 128/192/256 in s and f variants - through FaestKeyPairGenerator, FaestSigner and the matching key parameter classes. JCE plumbing is registered through BCPQC (KeyPairGenerator, Signature, KeyFactory, FaestParameterSpec, the FaestKey interface and the BC key classes), and twelve BC-arc OIDs cover the wire form through the usual converter plumbing, with loadPQCKeys() registering a key factory against each so the standard BC provider can decode FAEST-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- HAETAE post-quantum digital signature scheme (KpqC, the Korean Post-Quantum Cryptography competition). Lightweight implementation in org.bouncycastle.pqc.crypto.haetae covering all three parameter sets - HAETAE-2, HAETAE-3 and HAETAE-5, at NIST security levels 2, 3 and 5 - through HAETAEKeyPairGenerator, HAETAESigner and the matching key parameter classes. JCE plumbing is registered through BCPQC (KeyPairGenerator, Signature, KeyFactory, HaetaeParameterSpec, the HaetaeKey interface and the BC key classes, with per-parameter-set aliases), and three BC-arc OIDs under bc-sig.18 cover the SubjectPublicKeyInfo / PrivateKeyInfo wire form through the usual converter plumbing, with BouncyCastleProvider.loadPQCKeys() registering a key factory against each so the standard BC provider can decode HAETAE-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- Hawk post-quantum digital signature scheme (NIST PQC additional digital signatures process). Lightweight implementation in org.bouncycastle.pqc.crypto.hawk covering the three parameter sets hawk-256, hawk-512 and hawk-1024 through HawkKeyPairGenerator, HawkSigner and the matching key parameter classes; HawkSigner.generateSignature returns the signature bytes only, per the MessageSigner contract. JCE plumbing is registered through BCPQC (KeyPairGenerator, Signature, KeyFactory, HawkParameterSpec, the HawkKey interface and the BC key classes), and three BC-arc OIDs under bc-sig.15 cover the SubjectPublicKeyInfo / PrivateKeyInfo wire form through the usual converter plumbing, with BouncyCastleProvider.loadPQCKeys() registering a key factory against each so the standard BC provider can decode Hawk-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- QR-UOV (Quotient-Ring Unbalanced Oil and Vinegar) post-quantum digital signature scheme per the QR-UOV Round 2 NIST submission. Lightweight implementation in org.bouncycastle.pqc.crypto.qruov covering all twelve parameter sets across NIST security categories 1/3/5 through QRUOVKeyPairGenerator, QRUOVSigner and the matching key parameter classes. Each set is offered in both PRG flavours from the reference implementation, AES-CTR and SHAKE, and exercised against both NIST KAT trees. JCE plumbing is registered through BCPQC, exposing the canonical SHAKE-PRG variant, and twelve BC-arc OIDs under bc-sig.17 cover the wire form through the usual converter plumbing, with loadPQCKeys() registering a key factory against each so the standard BC provider can decode QR-UOV-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- PGPPublicKey.copyMinimal(KeyFingerPrintCalculator) and PGPPublicKeyRing.copyMinimal(KeyFingerPrintCalculator) return a copy of a public key (or public-key ring) carrying only the underlying public-key packets — user IDs, user-attribute packets, trust packets, key certifications and subkey-binding signatures are all dropped. The master/subkey distinction is preserved through the packet types (PublicKeyPacket vs PublicSubkeyPacket). Useful for producing a minimal key for OpenPGP v6 revocation-certificate distribution, stripping irrelevant user IDs / attribute packets from a key downloaded from a key server, or wire-size reduction (issue #1400).
- TestResourceFinder (the six per-module copies) now picks the bc-test-data root in this order: the bc.test.data.home system property, the BC_TEST_DATA_HOME environment variable, then the existing walk-up-from-working-directory search. When the property or environment variable is set its value is used directly, and a mistyped path now fails fast with a FileNotFoundException naming both the source and the bad path rather than silently falling through; the walk-up fallback preserves the default sibling-checkout convention, so existing setups keep working without configuration. The Gradle build no longer sets the property itself - supply it only when the layout differs from the sibling convention.
- Initial support for Merkle Tree Certificates, tracking the published draft-ietf-plants-merkle-tree-certs-05 (uint48 start/end widths in MTCProof, the CosignedMessage signature format, the id-pe-mtcCertificationAuthority CA-cert extension, and the extension list carried at the front of both MerkleTreeCertEntry and MTCProof). A new OID arc lives in org.bouncycastle.asn1.plants, its constants placeholders under Cloudflare's IANA PEN until IANA assigns the production OIDs. The high-level types in org.bouncycastle.cert.plants are JCA-free and lightweight-crypto-free operator abstractions: MTCSignature, MerkleTreeCertEntryExtension and MTCProof carry the wire structures with strict length and ordering enforcement, MTCCosignedMessage encodes the draft sec. 5.3.1 form, MerkleTreeHash is the hash-function operator with MerkleTreePrimitives implementing the RFC 6962-style subtree inclusion, consistency and covering algorithms over it, MTCSignatureVerifier and the cosigner verifier provider are the operator interfaces, and MerkleTreeCertificateValidator reconstructs the per-leaf inclusion proof and dispatches cosigner verification, with relying-party policy expressed as log-scoped trusted subtrees (sec. 7.4) and revoked serial-number ranges (sec. 7.5). LandmarkSequence, LandmarkCertificateManager and TrustAnchorIDs cover the issuance side. Lightweight bindings live in .plants.bc and JCA ones in .plants.jcajce, the latter taking a JcaJceHelper or Provider; the draft's ECDSA algorithm identifiers map to SHA{256,384}WITHPLAIN-ECDSA so the wire-format r||s bytes round-trip.
- MQOM v2.1 ("MQ on my Mind") post-quantum digital signature scheme (NIST PQC additional digital signatures process, round 2). Lightweight implementation in org.bouncycastle.pqc.crypto.mqom covering all thirty-six parameter sets - categories 1/3/5 across base fields gf2, gf16 and gf256, fast and short trade-offs and r3/r5 variants - through MQOMKeyPairGenerator, MQOMSigner and the matching key parameter classes. JCE plumbing is registered through BCPQC, and thirty-six BC-arc OIDs cover the wire form through the usual converter plumbing, with loadPQCKeys() registering a key factory against each so the standard BC provider can decode MQOM-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- UOV (Unbalanced Oil and Vinegar) post-quantum digital signature scheme (NIST PQC additional digital signatures process, round 2; pqov reference). Lightweight implementation in org.bouncycastle.pqc.crypto.uov covering all twelve parameter sets - security levels Is, Ip, III and V across the classic, pkc (compressed public key) and pkc_skc (compressed public key and seed-only secret key) encoding variants - through UOVKeyPairGenerator, UOVSigner and the matching key parameter classes. JCE plumbing is registered through BCPQC, and twelve BC-arc OIDs cover the wire form through the usual converter plumbing, with loadPQCKeys() registering a key factory against each so the standard BC provider can decode UOV-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- SQIsign (Short Quaternion and Isogeny Signature) post-quantum digital signature scheme (NIST PQC additional digital signatures process, round 2). Lightweight implementation in org.bouncycastle.pqc.crypto.sqisign covering the three NIST-API parameter sets sqisign_lvl1, lvl3 and lvl5 through SQIsignKeyPairGenerator, SQIsignSigner and the matching key parameter classes. The engine implements the full pipeline - quaternion-order and ideal arithmetic, the ideal-to-isogeny correspondence (Clapotis), theta-coordinate 2-dimensional isogenies and per-security-level GF(p^2) arithmetic - and reproduces the reference C implementation's KAT vectors byte-for-byte. JCE plumbing is registered through BCPQC with per-parameter-set aliases, and three BC-arc OIDs cover the wire form, with loadPQCKeys() registering a key factory against each. Note SQIsign signing and key generation are not constant-time: the arithmetic is BigInteger-based throughout and includes secret-dependent rejection and lattice-reduction loops, matching the reference implementation.
- SDitH (Syndrome-Decoding-in-the-Head) post-quantum digital signature scheme (NIST PQC additional digital signatures process, round 2). Lightweight implementation in org.bouncycastle.pqc.crypto.sdith covering all twelve parameter sets - both MPC structures, Hypercube and Threshold, across NIST categories 1/3/5 and base fields gf256 and p251 - through SDitHKeyPairGenerator, SDitHSigner and the matching key parameter classes, the signer dispatching between SDitHEngine (seed-tree plus per-iteration MPC simulation) and SDitHThresholdEngine (Shamir-style secret sharing plus a per-execution Merkle tree of party-share commitments). JCE plumbing is registered through BCPQC including parameter-locked SPIs for each set, and twelve BC-arc OIDs cover the wire form, with loadPQCKeys() registering a key factory against each; the generic KeyFactory.SDitH accepts X509EncodedKeySpec and PKCS8EncodedKeySpec for all twelve, threshold variants included (issue #2312).
- SDitH performance: the GF(256) scalar-times-vector multiply-accumulate at the heart of the matmul and the threshold engine's share arithmetic is now word-parallel and bitsliced - eight field elements per long through the constant-time mask-select / SWAR-xtime kernel in the new public org.bouncycastle.util.GF256, a companion to util.GF16 and the same primitive UOV's vecMadd256 uses - giving roughly 2x faster gf256 signing with byte-identical output. The GF(251^4) extension-field multiplication is flattened from a nested 16-multiplication tower to the optimized reference's 9-multiplication deferred-reduction form. Both changes are oracle-verified against the naive kernels and KAT-identical across all twelve parameter sets (issue #2312).
- Initial decode-only support for Certificate Transparency, covering both RFC 6962 (CT v1) and RFC 9162 (CT v2). New OID constants on X509ObjectIdentifiers for the Google 11129 arc - id_ce_ct_embeddedSCTList, id_ce_ct_precertPoison, id_kp_ct_precertSigning and id_ocsp_ct_sctList - plus the v2 1.3.101 arc. The new org.bouncycastle.cert.ct package carries the TLS-encoded wire types: SignedCertificateTimestamp and SignedCertificateTimestampList for v1, and TransItem, TransItemList, SignedCertificateTimestampDataV2 and SctExtension for v2. Each list type exposes a fromExtensions(Extensions) helper walking the corresponding extension OID and each wire type round-trips through getEncoded(); a misc example prints the embedded SCTs from a supplied certificate. Verifying an SCT against a log's STH is deliberately out of scope for this round (github #228).
- Initial support for draft-ietf-lamps-certdiscovery (Certificate Discovery in PKIX). Two new ASN.1 types under org.bouncycastle.asn1.x509 - CertDiscoveryMethod, a CHOICE over byUri, byInclusion and byLocalPolicy, and RelatedCertificateDescriptor, carrying that method plus optional intent, signature-algorithm and public-key-algorithm fields - plus a pkix-side RelatedCertificateDescriptorBuilder that emits an AccessDescription for the SubjectInfoAccess extension, its accessLocation an otherName GeneralName wrapping the descriptor. RelatedCertificateDescriptor.fromExtensions(Extensions) walks SIA on the read side. The draft OIDs are TBD in the document, so BC ships them as placeholders under the BC private arc; the constant names match what IANA is expected to assign, so production callers will need to swap the values once the draft progresses to RFC.
- SMIMESignedGenerator's class Javadoc now explicitly documents that the MimeMultipart it returns sources the signature body part through a JavaMail DataHandler callback, so JavaMail re-runs the CMS signing pipeline on every MimeMessage.writeTo. The cryptographic signature still verifies on every call, but the wire bytes are not stable across calls for non-deterministic signature schemes (ECDSA / DSA / RSA-PSS) or whenever a fresh signing-time signed attribute is captured per call. Callers needing byte-for-byte stable serialisation should serialise the message once and reuse the bytes, or use SMIMESignedWriter from the pkix module which captures the signature once into a buffer and emits the inline body part directly (issue #1460).
- BCrypt.generate(byte[], byte[], int) is now deprecated, and a new generate(byte[], byte[], int, boolean addTerminator) overload makes the bcrypt password-terminator decision explicit at the call site: true appends the spec-required 0x00 terminator byte before the EksBlowfishSetup password schedule, equivalent to feeding the input through BCrypt.passwordToByteArray(char[]), while false passes the supplied bytes through unchanged. The flag is ignored when the input is exactly 72 bytes - there is no room for the terminator within the bcrypt input limit, and two such inputs sharing a common prefix may collide as an unterminated shorter input does. The deprecated three-argument form delegates with false and is byte-for-byte unchanged, remaining available for test-vector validation and interop. For general password hashing use OpenBSDBCrypt (issue #1741).
- QCSyntaxExample in misc/src/main/java/org/bouncycastle/asn1/examples/ — decode-only worked example for the RFC 3739 qCStatements extension (1.3.6.1.5.5.7.1.3): reads an X.509 certificate (DER or PEM), walks the SEQUENCE OF QCStatement, and prints any id-qcs-pkixQCSyntax-v1 (RFC 3039) and id-qcs-pkixQCSyntax-v2 (RFC 3739) entries — for v2 decoding the statementInfo as SemanticsInformation (semanticsIdentifier + nameRegistrationAuthorities). Statements with any other statementId (for example the ETSI EN 319 412-5 statements) are printed as a raw ASN.1 dump so the example doubles as a starting point for inspecting unfamiliar qualified-certificate profiles (issue #1416).
- RFC 8702 "Use of the SHAKE One-Way Hash Functions in the Cryptographic Message Syntax (CMS)" KMAC support, completing the SHAKE-based CMS profile whose digest and signature halves were already in place. New CMSAlgorithm.KMACwithSHAKE128 / KMACwithSHAKE256 constants and a JceCMSMacCalculatorBuilder path that emits an absent-parameters AlgorithmIdentifier when the defaults are in effect and a KMACwithSHAKEnnn-params SEQUENCE when they are not. The new jcajce.spec.KMACParameterSpec carries the MAC size and customization string; the Mac.KMAC128 / KMAC256 SPIs now accept it on engineInit and re-instantiate the underlying lightweight engine with the supplied customization, tracking the configured output length. AlgorithmParameters for the four relevant OIDs decode the params SEQUENCE into that spec, Mac OID aliases are added so lookups by OID resolve, and EnvelopedDataHelper picks up the two RFC 8702 OIDs so CMS AuthenticatedData round-trips KMAC-with-SHAKE end to end.
- BIP-340 Schnorr signatures over secp256k1, the on-chain signature scheme used by Bitcoin Taproot. The lightweight org.bouncycastle.crypto.signers.BIP340Signer implements Signer for EC key parameters constrained to secp256k1, with the BIP-340 sec. 3 tagged-SHA-256 challenge, aux and nonce hashes, even-Y normalisation on both the private and the ephemeral side, x-only 32-byte public keys and fixed 64-byte r||s signatures - none of which match BC's ECDSA defaults. The signer is randomized by default, following the usual BC convention: a fresh 32-byte aux_rand is drawn per generateSignature() call, as sec. 3.2 recommends, from the SecureRandom supplied through ParametersWithRandom or from CryptoServicesRegistrar. Deterministic Schnorr is BIP-340 compliant but must be requested explicitly through new BIP340Signer(true) - the absence of a supplied SecureRandom does not silently select it. decodePublicKey(byte[32]) is the verifier-side helper, returning null for the cases sec. 3.1 defines as verification failures, and the BIP-340bis variable-length-message extension is supported (issue #1114).
- DeltaCertificateRequestAttributeValueBuilder (the draft-bonnell-lamps-chameleon-certs sec. 5 delta certificate request attribute builder) now exposes setExtensions(Extensions) so the [1] EXPLICIT extensions field can be populated; previously the builder could set only subject and signatureAlgorithm even though the parser already read the extensions field back. A new DeltaCertAttributeUtils.trimDeltaCertificateRequest(delta, baseRequest) helper encodes only the fields that differ from a base CSR (sec. 5.1), mirroring the cert-side trimDeltaCertificateDescriptor: subject and signatureAlgorithm are dropped when they equal the base, and the extensions field drops any extension whose criticality and DER value match the base, whose type is absent from the base, or which is the delta-certificate-request OID itself. The builder now also tags the extensions field [1] EXPLICIT to match the parser and the draft ASN.1 (issue #2234 / PR #2259).
- The GOST 34.10-2018 signature names are now registered as JCE aliases. GOST 34.10-2018 is the interstate (CIS/EAEU) re-adoption of GOST R 34.10-2012 and is algorithmically identical to it, using the same TC26 OIDs (1.2.643.7.1.1.1 / .1.1.2), so "ECGOST3410-2018", "ECGOST3410-2018-256", "ECGOST3410-2018-512" (and the dotted "GOST-3410-2018-\*" spellings) now resolve onto the existing ECGOST3410-2012 KeyFactory, KeyPairGenerator, Signature and KeyAgreement implementations. No new engine is introduced; the aliases exist so callers naming the 2018 standard can obtain the algorithm directly (issue #1028).
- The BC EdDSA Signature engines now honour an AlgorithmParameterSpec through setParameter, selecting the RFC 8032 instance: the prehash variants Ed25519ph / Ed448ph, and a context (Ed25519ctx, or the context Ed448 and the prehash variants permit). On JDK 15+ the standard java.security.spec.EdDSAParameterSpec is accepted, so BC can stand in for SunEC for prehash and context signing and verification, verified by cross-provider interop including byte-identical signatures. On any JDK the BC org.bouncycastle.jcajce.spec.EdDSAParameterSpec carries the same selectors through its new constructors and isPrehash() / getContext() accessors; a context longer than 255 bytes is rejected, and parameters must be set before initSign / initVerify. Previously setParameter threw UnsupportedOperationException and only the pure variants were reachable. The engines also now report the selected instance through getParameters(), and AlgorithmParameters round-trips the selectors; these parameters have no encoded form, RFC 8410 specifying an absent AlgorithmIdentifier parameters field, so getEncoded() throws (issue #2313).
- ARIAEngine (RFC 5794) block processing has been rewritten for speed while remaining byte-identical. The state is held in two longs, eliminating the per-block byte[16] and its arraycopies, and the round transform A(SL(.)) is computed by a SWAR multiply-broadcast: because the ARIA diffusion A is a GF(2) involution, A applied to one substituted byte is that byte replicated at the seven output positions of its column, which is exactly the byte times a precomputed 0x01-packed mask, so a round becomes the XOR over the 16 input bytes of S-box(byte) times mask. Only the existing 1KB S-boxes and 32 long constants stay resident - a full T-table form was tried and rejected, its larger tables losing to cache pressure against ARIA's already-cheap XOR diffusion. Measured around 1.3-1.4x throughput on HotSpot across JDK 8-25, neutral on GraalVM, benefiting every mode that wraps the engine; the key schedule is unchanged.
- Classic McEliece (org.bouncycastle.pqc.crypto.cmce) key generation and decapsulation are faster, byte-for-byte identically to before and with the scheme's constant-time properties preserved. CMCEEngine.pk_gen now runs the systematic-form Gaussian elimination over 64-bit words rather than single bytes, matching the reference implementation, so the row XOR clears 64 columns per step rather than 8, indexed only by public loop counters; mov_columns and the public-key extraction still operate on the byte form, synced once per key generation. CMCEEngine.decrypt now precomputes 1/g(L_i)^2 for the support once and shares it between its two syndrome passes rather than re-evaluating the Goppa polynomial twice per support element. The speedups are JIT-dependent: on HotSpot C2 keygen is up to about 1.2x and decapsulation 1.15-1.22x, while on GraalVM CE, whose vectoriser does not auto-widen the byte XOR, keygen is 3-5x faster.
- Initial Owl augmented PAKE in the new org.bouncycastle.crypto.agreement.owl package - an academic protocol (Hao, Bag, Chen, Lopez 2024) that extends J-PAKE with explicit user-registration and key-confirmation phases. The lightweight implementation supports the four-pass authentication exchange (OwlClient / OwlServer with their three payload types), the initial user-registration exchange and optional explicit key confirmation in both directions. Schnorr zero-knowledge proofs follow RFC 8235 over the OwlCurve elliptic-curve groups - OwlCurves.NIST_P256 is supplied and the constructor accepts any short-Weierstrass curve - with the shared primitives in OwlUtil. Owl is not yet an IETF standard; users wanting a standardised PAKE should prefer the existing J-PAKE or a stronger asymmetric PAKE. A worked exchange ships as misc/.../crypto/examples/OwlExample.java (PR #2168).
- RFC 9690 "Use of the RSA-KEM Algorithm in the Cryptographic Message Syntax (CMS)" support, obsoleting RFC 5990. RSA-KEM key transport now flows through the RFC 9629 KEMRecipientInfo pipeline already in place for ML-KEM and NTRU: the CMS layer was wired for the ISO 18033-2 id-kem-rsa AlgorithmIdentifier on both sides, but the JCE Cipher service it looked up by name was not registered. A new RSAKEMCipherSpi, registered as Cipher.RSA-KTS-KEM-KWS with aliases against id_kem_rsa, closes the gap: WRAP_MODE performs the ISO 18033-2 encapsulation, applies the KTSParameterSpec-supplied KDF (KDF2, KDF3 or HKDF, per sec. 3.2 and 4) to the shared secret with the CMSORIforKEMOtherInfo bytes as the otherInfo input, and AES-Wraps the CEK under the derived KEK, with UNWRAP_MODE the symmetric inverse. The mandatory-to-implement KDF3-SHA-256 with AES-128-WRAP, plus the other KDF variants and all three AES-WRAP sizes, are exercised by new round-trip tests.
- RFC 9709 "Encryption Key Derivation in the Cryptographic Message Syntax (CMS) Using HKDF with SHA-256" now interoperates with the new RFC 9690 KEM recipients. The existing id-alg-cek-hkdf-sha256 outer wrap, opt-in through JceCMSContentEncryptorBuilder.setEnableSha256HKdf(true), derives the effective CEK from the recipient-delivered IKM with info set to the DER of the inner contentEncryptionAlgorithm and the fixed salt "The Cryptographic Message Syntax", defending against the algorithm-substitution downgrade RFC 9709 sec. 1 describes. The recipient-side derivation in EnvelopedDataHelper now triggers for KEM recipients as well as KeyTrans, KEK and KeyAgree, and a new test case exercises RSA-KEM layered with the content wrap end to end.
- Experimental support for Composite ML-KEM (draft-ietf-lamps-pq-composite-kem), which pairs ML-KEM with a traditional KEM - RSA-OAEP, ECDH, X25519 or X448 - so the derived secret stays secure while either component does, with the sec. 3.4 combiner ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label). The BC provider registers each of the twelve composite parameter sets, under both its algorithm name and OID, as a KeyPairGenerator producing CompositePublicKey / CompositePrivateKey pairs whose components are the ML-KEM key followed by the traditional key, a KeyGenerator that encapsulates and decapsulates through KEMGenerateSpec / KEMExtractSpec, and a KeyFactory for X.509 / PKCS#8 keys. Algorithm names follow the draft, so the brainpool sets spell the curve out in full as the composite ML-DSA names do, with the abbreviated BP256 / BP384 forms they were first registered under kept as aliases; the IANAObjectIdentifiers constants follow suit, the abbreviated spellings becoming deprecated aliases. Verified against the draft Appendix F test vectors.
- RFC 9474 RSA Blind Signatures (RSABSSA), a blind signature protocol producing standard RSASSA-PSS signatures. The lightweight implementation in org.bouncycastle.crypto.signers covers the four named variants of sec. 5 through the RSABlindSignatureParameters variant class plus RSABlindSignatureClient, whose single blind call covers Prepare and Blind ahead of finalize, and RSABlindSignatureServer, whose BlindSign performs the sec. 4.3 step 3 RSAVP1 self-check so a CRT fault is caught before the value leaves the server. The randomised variants prepend a 32-byte prefix to the message and the PSSZERO variants use an empty EMSA-PSS salt; Finalize verifies the unblinded signature through standard RSASSA-PSS before returning, so a fault surviving BlindSign is caught client-side too. Known-answer tested against all four RFC 9474 Appendix A vectors, with a worked client and server exchange in misc.
- DSTU7564Digest (Kupyna, DSTU 7564:2014) round function has been optimised by fusing its shiftRows, subBytes and mixColumns layers into eight precomputed 256-entry T-tables (the same construction Whirlpool uses for C0..C7): each output column is now the XOR of eight table lookups, replacing the per-column S-box reassembly and the SWAR mixColumn arithmetic, with shiftRows folded into the source-column selection. Output is byte-for-byte unchanged for both the 256/384-bit (512-bit state) and 512-bit (1024-bit state) variants, and DSTU7564Mac benefits transparently; measured throughput improves by roughly 1.2x-1.3x across JDK 8 through 25 (and GraalVM).
- OpenSSHPrivateKeyUtil.parsePrivateKeyBlob can now decrypt passphrase-protected openssh-key-v1 private keys. A new parsePrivateKeyBlob(byte[], byte[] passphrase) overload derives the cipher key and IV with the OpenSSH bcrypt_pbkdf KDF - the only KDF the format defines - and decrypts the private section; the supported ciphers are the aes-ctr and aes-cbc sizes, 3des-cbc, and the AEAD aes-gcm and chacha20-poly1305 forms, whose tag is verified before the key is returned, so a wrong passphrase is rejected through the tag or the checkint guard rather than silently mis-decrypted. The KDF is exposed for reuse as the public static BCrypt.pbkdfGenerate, cross-checked against the OpenBSD reference. The support is also wired through the JCA layer: OpenSSHPrivateKeySpec gains a (byte[], char[]) constructor and the RSA, DSA, EC and EdDSA KeyFactory implementations thread the passphrase through, the EC one now also accepting the openssh-key-v1 format it previously handled only in SEC1 form (issue #1733).
- AIMer post-quantum digital signature scheme (KpqC Round 2, an MPC-in-the-head signature built on the AIM one-way function). Lightweight implementation in org.bouncycastle.pqc.crypto.aimer covering all six parameter sets - aimer-128, -192 and -256, each in fast and short flavours at NIST categories 1/3/5 - through AIMerKeyPairGenerator, AIMerSigner and the matching key parameter classes. JCE plumbing is registered through BCPQC, and six BC-arc OIDs under bc-sig.20 cover the wire form through the usual converter plumbing, with loadPQCKeys() registering a key factory against each so the standard BC provider can decode AIMer-bearing certificates and PKCS#8 keys without BCPQC in the lookup chain.
- The Gradle build can now generate CycloneDX 1.6 bill-of-materials documents for the release artifacts, through the generateCbom and generateSbom tasks. generateCbom produces a Cryptographic Bill of Materials for the provider jar by introspecting the JCA service tables of both providers in the freshly built jar: one cryptographic-asset component per algorithm, with the CycloneDX primitive classification, the crypto functions each algorithm exposes, and the OIDs recovered from the provider's Alg.Alias registrations. generateSbom mirrors the published Maven BOM with one component per published module jar - the set read from the bom project's platform constraints and the coordinates from each module's publication, so it cannot drift from what is published - carrying hashes matching the Maven checksum files, the declared external dependencies and the inter-module dependency graph, with the matching .pom and .module files produced alongside. Both validate against the CycloneDX 1.6 schema and are byte-for-byte reproducible: the serial number is a name-based UUID over the artifact purl and the timestamp is the git commit time, overridable through SOURCE_DATE_EPOCH.
- A new certificate-diagnostics API, org.bouncycastle.cert.X509CertificateReviewer, reports every structural problem in a certificate rather than just the first. The strict parse path is unchanged - org.bouncycastle.asn1.x509.Certificate / TBSCertificate / Extensions still fail fast on the first defect and never return a partially-parsed object - but reviewStructure(byte[]) / reviewStructure(ASN1Sequence) run the same single-sourced checks in collecting mode and return a Review: a list of Findings (each pairing a location with the exception the strict path would have thrown, in parse order) plus the recovered X509CertificateHolder when, and only when, the strict path would also accept it. It is the parse-side analogue of PKIXCertPathReviewer (issues #1508, #1511).
- The PKCS12 keystore's default PBE iteration count has been raised from 51200 to 600000, in line with current OWASP guidance for PBKDF1-style iterated SHA-256 derivations; keystores written with the old default (and any count up to the org.bouncycastle.pkcs12.max_it_count cap) continue to load. The maximum-iteration-count property name is now exposed as the Properties.PKCS12_MAX_IT_COUNT constant.
- The Mayo signature algorithm's object identifiers have moved from the interim BC arc to the OQS interop-registered values (1.3.9999.8.n.3 for MAYO-1/2/3/5), Mayo can now be used for CMS signing and X.509 certificate work (the DefaultSignatureAlgorithmIdentifierFinder / DefaultSignatureNameFinder tables and the BC-provider key-info converters cover the new OIDs), and the hyphenated MAYO-1/MAYO-2/MAYO-3/MAYO-5 algorithm names are registered alongside the existing forms.
- The low-level Ed25519 implementation (org.bouncycastle.math.ec.rfc8032.Ed25519) gains an ExpandedKey representation: expandPrivateKey / generatePrivateKey produce the pre-hashed expanded form, and generatePublicKey / sign overloads consume it directly. This lets a caller expand the 32-byte seed once and sign many messages without re-running the SHA-512 key expansion per signature, and supports deployments that hold only the expanded key.
- A new org.bouncycastle.crypto.agreement.ECDHRawAgreement implements the RawAgreement interface for plain ECDH, writing the fixed-length X9.63 field-element encoding of the shared secret directly into a caller-supplied buffer (getAgreementSize() bytes) - the natural fit for HPKE/TLS-style KDF pipelines that consume the raw shared secret, avoiding the BigInteger round trip of ECDHBasicAgreement.
- The ML-DSA lightweight implementation has been given a performance refactor (including merging the PolyVecK/PolyVecL vector types) that is byte-identical on the wire, together with a constant-time audit of the secret-dependent paths.
- Safe-prime parameter generation for DH and ElGamal (DHParametersGenerator / ElGamalParametersGenerator) is substantially faster: candidate search now sieves both p and (p-1)/2 together, and g = 2 is chosen when it is a quadratic residue, avoiding a full generator search.
- DefaultAlgorithmNameFinder (org.bouncycastle.operator) now maps the NIST AES-GCM and AES-CCM content-encryption OIDs to the conventional "AES-128/GCM" ... "AES-256/CCM" names instead of falling back to the dotted OID string (issue #1763).
- The ASN.1 stream-safety limits are now publicly addressable: the maximum nested-construction depth and the maximum declared object length are controlled by the org.bouncycastle.asn1.max_cons_depth and org.bouncycastle.asn1.max_limit system properties, exposed as the Properties.ASN1_MAX_CONS_DEPTH and Properties.ASN1_MAX_LIMIT constants (values and defaults unchanged).
- The EST client's TLS channel authorizer (org.bouncycastle.est.jcajce) has been hardened in line with RFC 9525 (which obsoletes RFC 6125): a wildcard is accepted only when the single '\*' is the complete content of the left-most label and it must match exactly one non-empty label, so partial wildcards ("f\*o.example"), wildcards in inner labels, and wildcards spanning label boundaries or a known public suffix are rejected (issue #1495).

### 2.4.4 Security Fixes

- CVE-2026-8763 - Name Constraints bypass via trailing dot in rfc822Name and URI.
- CVE-2026-12185 - BKS/UBER keystore allocates from untrusted lengths before integrity check.
- CVE-2026-12802 - CMS AuthEnvelopedData fails to enforce tag-length on decryption.
- CVE-2026-12803 - KCCMBlockCipher MAC does not bind nonce when AAD is absent (cross-nonce AEAD forgery).
- CVE-2026-12816 - IESEngine stream-mode MAC forgery via length-dependent KDF split.
- CVE-2026-12817 - OpenPGP AEAD decryption skips final tag on chunk-aligned data.
- CVE-2026-12852 - MLS wire decoder allocates attacker-declared opaque length before bounds check.
- CVE-2026-12860 - RSA PKCS#1 verification skips last two hash bytes in NULL-omitted path.
- CVE-2026-13506 - Lazy ASN.1 sequence forcing resets nesting-depth guard.
- CVE-2026-13586 - PKCS#12 MAC and bag-decryption KDF iteration-count bound (DoS).
- CVE-2026-14682 - Possible OOM from unbounded up-front allocation on a definite-length read.
- CVE-2026-15055 - PKCS#8 / PBES2 decryptors honour unbounded KDF cost from input.
- CVE-2026-58059 - Quadratic-time escaping when stringifying X.500 distinguished names.
- CVE-2026-58060 - HSS public-key level count unbounded, enabling huge allocation on verify.
- CVE-2026-58061 - CCM-family modes write plaintext to caller buffer before tag check.
- CVE-2026-58062 - Stapled OCSP response accepted without binding to the checked certificate.
- CVE-2026-58063 - BCFKS keystore load honours unbounded KDF cost from untrusted file.
- CVE-2026-59638 - JSSE hostname verifier CN-fallback enabled by default despite documented opt-in.
- CVE-2026-59639 - CMS verifySignatures returns true for SignedData with zero signers.
- CVE-2026-59640 - OpenPGP CFB quick-check oracle active on symmetric/session-key paths.
- CVE-2026-59641 - S/MIME validator trusts signer-asserted signingTime for path validation.
- CVE-2026-59642 - CMS AuthenticatedData content not bound to MAC when authAttrs present.
- CVE-2026-59643 - OpenPGP inline-signature policy failures silently ignored.
- CVE-2026-59644 - MLS hash-ratchet honours arbitrary 32-bit generation counter from sender.
- CVE-2026-59645 - OER parser recurses without depth limit on self-referential IEEE 1609.2 schema.
- CVE-2026-59646 - DTLS handshake reassembler allocates buffer from unchecked 24-bit length.
- CVE-2026-59647 - CRMF/CMP password-MAC honours unbounded iteration count.
- CVE-2026-59648 - OpenPGP Argon2 S2K honours attacker-chosen memory and passes.
- CVE-2026-59649 - OpenPGP user-attribute subpacket length bounded only by JVM max memory.
- CVE-2026-59650 - MTI/A0 DH agreement exponentiates unvalidated peer value.
- CVE-2026-59651 - BKS keystore accepts legacy version with 16-bit integrity MAC key.
- CVE-2026-59652 - LDAP filter injection in legacy jdk1.4 LDAPStoreHelper.

### 2.4.5 Additional Notes

- The standardised PQC algorithms ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, and CMCE have been repackaged under org.bouncycastle.crypto and the versions under org.bouncycastle.crypto.pqc have been deprecated. These deprecated versions will be removed in BC 1.86.

<a id="r1rv84"></a>

### 2.5.1 Version

Release: 1.84\
Date: 2026, April 14th

### 2.5.2 Defects Fixed

- Random numbers being generated for DSTU4145 signature calculations were 1 bit shorter than they could be. The code has been corrected to allow the generated numbers to occupy the full numeric range available.
- HKDF implementation has been corrected to use multiple IKMs if available.
- CompositePublic/PrivateKey builders had an issue identifying brainpool and EdDSA curves from the algorithm names due to an error in the OID mapping table. This has been fixed.
- S/MIME: Fix AuthEnveloped support for AES192/GCM and AES256/GCM.
- CMS: Use implicit tag for AuthEnvelopedData.authEncryptedContentInfo.encryptedContent.
- Fixed Strings.split to handle delimiters at position 0.
- Fixed FrodoKEM error sampling to be constant-time.
- Fixed PKIXNameConstraintValidator to treat a DNS name as intersecting itself.
- Fixed PKCS12 key stores not calling getInstance with the original provider (which was forcing provider registration).
- A resource leak due to the SMIMESigned constructor leaving background threads hanging on MessagingException has been fixed.
- OpenPGP: Fixed an issue where a custom signature creation time was ignored when generating message signatures.
- OpenPGP: Fixed SKESK encoding for direct-S2K-encrypted messages.

### 2.5.3 Additional Features and Functionality

- In line with JVM changes, KEM support has been backported to Java 17.
- BCJSSE: Configurable (client) early key_share groups via BCSSLParameters.earlyKeyShares or "org.bouncycastle.jsse.client.earlyKeyShares" system property.
- BCJSSE: Support for curveSM2MLKEM768 hybrid NamedGroup in TLS 1.3 per draft-yang-tls-hybrid-sm2-mlkem-03.
- BCJSSE: Log when default cipher suites are disabled.
- BCJSSE: Experimental support for ShangMi crypto in TLS 1.3 per RFC 8998 (not enabled by default).
- CMS: Added CMSAuthEnvelopedDataStreamGenerator.open taking an explicit content type.
- HKDF: Provider support for HKDFParameterSpec.Expand.
- Added initial support for RFC 9380 (Hashing to Elliptic Curves); see org.bouncycastle.crypto.hash2curve .
- PKCS12: Added default max iteration count of 5,000,000 (configurable via "org.bouncycastle.pkcs12.max_it_count" property).
- TLS: Use javax.crypto.KEM API (when available) to access ML-KEM implementation (incl. hybrids).
- A new KeyStore, PKCS12-PBMAC1, has been added which defaults to using PBMAC1 and supports RFC 9879.
- A new property "org.bouncycastle.asn1.max_cons_depth" has been added to allow setting of the maximum nesting for SETs/SEQUENCESs in ASN.1. Default is 32.
- A new property "org.bouncycastle.asn1.max_limit" has been added to allow setting of the stream size of ASN.1 encodings. The value can be either in bytes, or appended with k (1 kilobyte blocks), m (1 megabyte blocks), or g (1 gigabyte blocks).
- Added NTRU+ support to the lightweight PQC API and the BCPQC provider.
- Added SM4 key wrap/unwrap mode, SM2 key exchange, and logging to SM2Signer.
- OpenPGP: Added encryption‑key filtering by purpose, a new OpenPGPKey constructor, KeyPassphraseProvider‑based passphrase change, wildcard (anonymous) recipient handling, and Web‑of‑Trust methods for third‑party signature chains and delegations.
- CMSSignedDataStreamGenerator can now support the generation of DER/DL encoded SignedData objects (note memory restrictions still apply).
- It is now possible to add extra digest alorithm IDs to CMSSignedDataStreamGenerator when required.

### 2.5.4 Security Fixes

- CVE-2025-14813 - GOSTCTR implementation unable to process more than 255 blocks correctly.
- CVE-2026-0636 - LDAP Injection Vulnerability in LDAPStoreHelper.java.
- CVE-2026-3505 - Unbounded PGP AEAD chunk size leads to pre-auth resource exhaustion.
- CVE-2026-5588 - PKIX draft CompositeVerifier accepts empty signature sequence as valid.
- CVE-2026-5598 - Non-constant time comparisons risk private key leakage in FrodoKEM.

### 2.5.5 Additional Notes

- DSA was recently deprecated by NIST and several users have requested that we move to an RSA signing certificate for provider signing instead of our current DSA one. We are grateful to report that Oracle have been very supportive of this and issued us a second RSA certificate based on a new RSA key for signing providers. Providers signed with the previous DSA key will continue to work as before.
- This will be the last release which will recognise Dilithium and SphincsPlus in the BC provider, the Kyber wrapper (which is just ML-KEM) will also be removed. The algorithms won't be deleted in 1.85, but will only be accessible via the low-level APIs and deleted in a later release.

<a id="r1rv83"></a>

### 2.6.1 Version

Release: 1.83\
Date: 2025, November 27th.

### 2.6.2 Defects Fixed

- Attempting to check a password on a stripped PGP key would throw an exception. Checking the password on such a key will now always return false.
- Fixed an issue in KangarooTwelve where premature absorption caused erroneous 168-byte padding; absorption is now delayed so correct final-byte padding is applied.
- BCJSSE: Fix supported_versions creation for renegotiation handshake.
- (D)TLS: Reneg info now only offered with pre-1.3.

### 2.6.3 Additional Features and Functionality

- A generic "COMPOSITE" algorithm name has been added as a JCA Signature algorithm. The algorithm will identify the composite signature to use from the composite key passed in.
- The composite signatures implementation has been updated to the final draft and now follows the submitted standard.
- Support for the generation and use as trust anchors has been added for certificate signatures with id-alg-unsigned as the signature type.
- Support for CMP direct POP for encryption keys using challenge/response has been added to the CMP/CRMF APIs.
- Support for SupportedCurves attribute added to the BC provider
- BCJSSE: Added support for SLH-DSA signature schemes in TLS 1.3 per draft-reddy-tls-slhdsa-01.
- Support has been added for the Java 25 KDF API (current algorithms, PBKDF2, SCRYPT, and HKDF).
- Support for composite signatures is now included in CMS and timestamping.
- It is now possible to disable the Lenstra check in RSA where the public key is not available via the system/security property "org.bouncycastle.rsa.no_lenstra_check".

<a id="r1rv82"></a>

### 2.7.1 Version

Release: 1.82\
Date: 2025, 17th September.

### 2.7.2 Defects Fixed

- SNOVA and MAYO are now correctly added to the JCA provider module-info file.
- TLS: Avoid nonce reuse error in JCE AEAD workaround for pre-Java7.
- BCJSSE: Session binding map is now shared across all stages of the session lifecycle (SunJSSE compatibility).
- The CMCEPrivateKeyParameters#reconstructPublicKey method was returning an empty byte array. It now returns an encoding of the public key.
- CBZip2InputStream no longer auto-closes at end-of-contents.
- The BC CertPath implementation was eliminating certificates on the bases of the Key-ID. This is not in accordance with RFC 4158 and has been fixed.
- Support for the previous set of libOQS Falcon OIDs has been restored.
- The BC CipherInputStream could throw an exception if asked to handle an AEAD stream consisting of the MAC only. This has been fixed.
- Some KeyAgreement classes were missing in the Java 11 class hierarchy. This has been fixed.
- A typo in a constant name in the HPKE class has been fixed and the old constant deprecated.
- Fuzzing analysis has been done on the OpenPGP API and additional code has been added to prevent escaping exceptions.

### 2.7.3 Additional Features and Functionality

- SHA3Digest, CSHAKE, TupleHash, KMAC now provide support for Memoable and EncodableService.
- BCJSSE: Added support for integrity-only cipher suites in TLS 1.3 per RFC 9150.
- BCJSSE: Added support for system properties "jdk.tls.client.maxInboundCertificateChainLength" and "jdk.tls.server.maxInboundCertificateChainLength".
- BCJSSE: Added support for ML-DSA signature schemes in TLS 1.3 per draft-ietf-tls-mldsa-00.
- The Composite post-quantum signatures implementation has been updated to the latest draft (07) [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs).
- "\<name\>\_PREHASH" implementations are now provided for all composite signatures to allow the hash of the data to be used instead of the actual data in signature calculation.
- The gradle build can now be used to generate an Bill of Materials (BOM) file.
- It is now possible to configure the SignerInfoVerifierBuilder used by the SignedMailValidator class.
- The Ascon family of algorithms has been updated with the latest published changes.
- Composite signature keys can now be constructed from the individual keys of the algorithms composing the composite.
- PGPSecretKey, PGPSignatureGenerator now support version 6.
- Further optimisation work has been done on ML-KEM public key validation.
- Zeroization of passwords in the JCA PKCS12 key store has been improved.
- The "org.bouncycastle.drbg.effective_256bits_entropy" property has been added for platforms where the entropy source is not producing 1 full bit of entropy per bit and additional bits are required (default value 282).
- Support has been added to the CMS content encryptors to allow a generated key to be passed in, rather than always having them generate their own.
- OpenPGPKeyGenerator now allows for the use of empty UserIDs (version 4 compatibility).
- The HQC KEM has been updated with the latest draft updates.

### 2.7.4 Additional Notes

- The legacy post-quantum package has now been removed.

<a id="r1rv81"></a>

### 2.8.1 Version

Release: 1.81\
Date: 2025, 4th June.

### 2.8.2 Defects Fixed

- A potention NullPointerException in the KEM KDF KemUtil class has been removed.
- Overlapping input/output buffers in doFinal could result in data corruption. This has been fixed.
- Fixed Grain-128AEAD decryption incorrectly handle MAC verification.
- Add configurable header validation to prevent malicious header injection in PGP cleartext signed messages; Fix signature packet encoding issues in PGPSignature.join() and embedded signatures while phasing out legacy format.
- Fixed ParallelHash initialization stall when using block size B=0.
- The PRF from the PBKDF2 function was been lost when PBMAC1 was initialized from protectionAlgorithm. This has been fixed.
- The lowlevel DigestFactory was cloning MD5 when being asked to clone SHA1. This has been fixed.

### 2.8.3 Additional Features and Functionality

- XWing implementation updated to draft-connolly-cfrg-xwing-kem/07/
- Further support has been added for generation and use of PGP V6 keys
- Additional validation has been added for armored headers in Cleartext Signed Messages.
- The PQC signature algorithm proposal Mayo has been added to the low-level API and the BCPQC provider.
- The PQC signature algorithm proposal Snova has been added to the low-level API and the BCPQC provider.
- Support for ChaCha20-Poly1305 has been added to the CMS/SMIME APIs.
- The Falcon implementation has been updated to the latest draft.
- Support has been added for generating keys which encode as seed-only and expanded-key-only for ML-KEM and ML-DSA private keys.
- Private key encoding of ML-DSA and ML-KEM private keys now follows the latest IETF draft.
- The Ascon family of algorithms has been updated to the initial draft of SP 800-232. Some additional optimisation work has been done.
- Support for ML-DSA's external-mu calculation and signing has been added to the BC provider.
- CMS now supports ML-DSA for SignedData generation.
- Introduce high-level OpenPGP API for message creation/consumption and certificate evaluation.
- Added JDK21 KEM API implementation for HQC algorithm.
- BCJSSE: Strip trailing dot from hostname for SNI, endpointID checks.
- BCJSSE: Draft support for ML-KEM updated (draft-connolly-tls-mlkem-key-agreement-05).
- BCJSSE: Draft support for hybrid ECDHE-MLKEM (draft-ietf-tls-ecdhe-mlkem-00).
- BCJSSE: Optionally prefer TLS 1.3 server's supported_groups order (BCSSLParameters.useNamedGroupsOrder).

<a id="r1rv80"></a>

### 2.9.1 Version

Release: 1.80\
Date: 2025, 14th January.

### 2.9.2 Defects Fixed

- A splitting issue for ML-KEM lead to an incorrect size for kemct in KEMRecipientInfos. This has been fixed.
- The PKCS12 KeyStore has been adjusted to prevent accidental doubling of the Oracle trusted certificate attribute (results in an IOException when used with the JVM PKCS12 implementation).
- The SignerInfoGenerator copy constructor was ignoring the certHolder field. This has been fixed.
- The getAlgorithm() method return value for a CompositePrivateKey was not consistent with the corresponding getAlgorithm() return value for the CompositePrivateKey. This has been fixed.
- The international property files were missing from the bcjmail distribution. This has been fixed.
- Issues with ElephantEngine failing on processing large/multi-block messages have been addressed.
- GCFB mode now fully resets on a reset.
- The lightweight algorithm contestants: Elephant, ISAP, PhotonBeetle, Xoodyak now support the use of the AEADParameters class and provide accurate update/doFinal output lengths.
- An unnecessary downcast in CertPathValidatorUtilities was resulting in the ignoring of URLs for FTP based CRLs. This has been fixed.
- A regression in the OpenPGP API could cause NoSuchAlgorithmException to be thrown when attempting to use SHA-256 in some contexts. This has been fixed.
- EtsiTs1029411TypesAuthorization was missing an extension field. This has been added.
- Interoperability issues with single depth LMS keys have been addressed.

### 2.9.3 Additional Features and Functionality

- CompositeSignatures now updated to draft-ietf-lamps-pq-composite-sigs-03.
- ML-KEM, ML-DSA, SLH-DSA, and Composite private keys now use raw encodings as per the latest drafts from IETF 121: draft-ietf-lamps-kyber-certificates-06, draft-ietf-lamps-dilithium-certificates-05, and draft-ietf-lamps-x509-slhdsa.
- Initial support has been added for RFC 9579 PBMAC1 in the PKCS API.
- Support has been added for EC-JPAKE to the lightweight API.
- Support has been added for the direct construction of S/MIME AuthEnvelopedData objects, via the SMIMEAuthEnvelopedData class.
- An override "org.bouncycastle.asn1.allow_wrong_oid_enc" property has been added to disable new OID encoding checks (use with caution).
- Support has been added for the PBEParemeterSpec.getParameterSpec() method where supported by the JVM.
- ML-DSA/SLH-DSA now return null for Signature.getParameters() if no context is provided. This allows the algorithms to be used with the existing Java key tool.
- HQC has been updated to reflect the reference implementation released on 2024-10-30.
- Support has been added to the low-level APIs for the OASIS Shamir Secret Splitting algorithms.
- BCJSSE: System property "org.bouncycastle.jsse.fips.allowGCMCiphersIn12" no longer used. FIPS TLS 1.2 GCM suites can now be enabled according to JcaTlsCrypto#getFipsGCMNonceGeneratorFactory (see JavaDoc for details) if done in alignment with FIPS requirements.
- Support has been added for OpenPGP V6 PKESK and message encryption.
- PGPSecretKey.copyWithNewPassword() now includes AEAD support.
- The ASCON family of algorithms have been updated in accordance with the published FIPS SP 800-232 draft.

<a id="r1rv79"></a>

### 2.10.1 Version

Release: 1.79\
Date: 2024, 30th October.

### 2.10.2 Defects Fixed

- Leading zeroes were sometimes dropped from Ed25519 signatures leading to verification errors in the PGP API. This has been fixed.
- Default version string for Armored Output is now set correctly in 18on build.
- The Elephant cipher would fail on large messages. This has been fixed.
- CMSSignedData.replaceSigners() would re-encode the digest algorithms block, occassionally dropping ones where NULL had been previously added as an algorithm parameter. The method now attempts to only use the original digest algorithm identifiers.
- ERSInputStreamData would fail to generate the correct hash if called a second time with a different hash algorithm. This has been fixed.
- A downcast in the CrlCache which would cause FTP based CRLs to fail to load has been removed.
- ECUtil.getNamedCurveOid() now trims curve names of excess space before look up.
- The PhotonBeetle and Xoodyak digests did not reset properly after a doFinal() call. This has been fixed.
- Malformed AlgorithmIdentifiers in CertIDs could cause caching issues in the OCSP cache. This has been fixed.
- With Java 21 a provider service class will now be returned with a null class name where previously a null would have been returned for a service. This can cause a NullPointerException to be thrown by the BC provider if a non-existant service is requested. This issue has now been worked around.
- CMS: OtherKeyAttribute.keyAttr now treated as optional.
- CMS: EnvelopedData and AuthEnvelopedData could calculate the wrong versions. This has been fixed.
- The default version header for PGP armored output did not carry the correct version string. This has been fixed.
- In some situations the algorithm lookup for creating PGPDigestCalculators would fail due to truncation of the algorithm name. This has been fixed.

### 2.10.3 Additional Features and Functionality

- Object Identifiers have been added for ML-KEM, ML-DSA, and SLH-DSA.
- The PQC algorithms, ML-KEM, ML-DSA (including pre-hash), and SLH-DSA (including pre-hash) have been added to the BC provider and the lightweight API.
- A new spec, ContextParameterSpec, has been added to support signature contexts for ML-DSA and SLH-DSA.
- BCJSSE: Added support for security property "jdk.tls.server.defaultDHEParameters" (disabled in FIPS mode).
- BCJSSE: Added support for signature_algorithms_cert configuration via "org.bouncycastle.jsse.client.SignatureSchemesCert" and "org.bouncycastle.jsse.server.SignatureSchemesCert" system properties or BCSSLParameters property "SignatureSchemesCert".
- BCJSSE: Added support for boolean system property "org.bouncycastle.jsse.fips.allowGCMCiphersIn12" (false by default).
- (D)TLS: Remove redundant verification of self-generated RSA signatures.
- CompositePrivateKeys now support the latest revision of the composite signature draft.
- Delta Certificates now support the latest revision of the delta certificate extension draft.
- A general KeyIdentifier class, encapsulating both PGP KeyID and the PGP key fingerprint has been added to the PGP API.
- Support for the LibrePGP PreferredEncryptionModes signature subpacket has been added to the PGP API.
- Support for Version 6 signatures, including salts, has been added to the PGP API.
- Support for the PreferredKeyServer signature supacket has been added to the PGP API.
- Support for RFC 9269, "Using KEMs in Cryptographic Message Syntax (CMS)", has been added to the CMS API.
- Support for the Argon2 S2K has been added to the PGP API.
- The system property "org.bouncycastle.pemreader.lax" has been introduced for situations where the BC PEM parsing is now too strict.
- The system property "org.bouncycastle.ec.disable_f2m" has been introduced to allow F2m EC support to be disabled.
- ETSIQCObjectIdentifiers now defines id_etsi_qcs_QcCClegislation (0.4.0.1862.1.7), the ETSI EN 319 412-5 qualified-certificate statement identifying the country legislation under which the qualified certificate was issued (issue #1467).

<a id="r1rv78d1"></a>

### 2.11.1 Version

Release: 1.78.1\
Date: 2024, 18th April.

### 2.11.2 Defects Fixed

- The new dependency of the the PGP API on the bcutil jar was missing from the module jar, the OSGi manifest, and the Maven POM. This has been fixed.
- Missing exports and duplicate imports have been added/removed from the OSGi manifests.
- The OSGi manifests now have the same bundle IDs as 1.77 and lock down dependencies to the equivalent variations.
- A check in the X.509 Extensions class preventing the parsing of empty extensions has been removed.

<a id="r1rv78"></a>

### 2.12.1 Version

Release: 1.78\
Date: 2024, 7th April.

### 2.12.2 Defects Fixed

- Issues with a dangling weak reference causing intermittent NullPointerExceptions in the OcspCache have been fixed.
- Issues with non-constant time RSA operations in TLS handshakes have been fixed (CVE-2024-30171).
- Issue with Ed25519, Ed448 signature verification causing intermittent infinite loop have been fixed (CVE-2024-30172).
- Issues with non-constant time ML-KEM implementation ("Kyber Slash") have been fixed (CVE-2024-14041).
- Importing an EC certificate or key with specially crafted F2m parameters could cause high CPU usage during parameter evaluation. The F2m field size is now bounded, defaulting to 1142 bits (twice 571) and configurable using the org.bouncycastle.ec.max_f2m_field_size system property (CVE-2024-29857).
- Align ML-KEM input validation with FIPS 203 IPD requirements.
- Make PEM parsing more forgiving of whitespace to align with RFC 7468 - Textual Encodings of PKIX, PKCS, and CMS Structures.
- Fix CCM length checks with large nonce sizes (n=12, n=13).
- EAC: Fixed the CertificateBody ASN.1 type to support an optional Certification Authority Reference in a Certificate Request.
- ASN.1: ObjectIdentifier (also Relative OID) parsing has been optimized and the contents octets for both types are now limited to 4096 bytes.
- BCJSSE: Fixed a missing null check on the result of PrivateKey.getEncoded(), which could cause issues for HSM RSA keys.
- BCJSSE: When endpoint identification is enabled and an SSL socket is not created with an explicit hostname (as happens with HttpsURLConnection), hostname verification could be performed against a DNS-resolved IP address. This has been fixed (CVE-2024-34447).
- The missing module import of java.logging to the provider module has been added.
- GOST ASN.1 public key alg parameters are now compliant with [RFC 9215](https://datatracker.ietf.org/doc/rfc9215/).
- An off-by-one error in the encoding for EccP256CurvePoint for ITS has been fixed.
- PEM Parser now enforces PEM headers to start at the beginning of the line to be meaningful.

### 2.12.3 Additional Features and Functionality

- An implementation of MLS ([RFC 9420 - The Messaging Layer Security Protocol](https://datatracker.ietf.org/doc/rfc9420/)) has been added as a new module.
- NTRU now supports NTRU-HPS4096-1229 and NTRU-HRSS-1373.
- Improvements to PGP support, including Camellia key wrapping and Curve25519, Curve448 key types (including XDH with HKDF).
- Added initial support for ML-KEM in TLS.
- Added XWing hybrid KEM construction (X25519 + ML-KEM-768).
- Introduced initial KEMSpi support (NTRU, SNTRU Prime) for JDK 21+.
- Introduced initial composite signature support for X509 Certificates.
- PKCS#12 now supports PKCS12-AES256-AES128, PKCS12-AES256-AES128-GCM, PKCS12-DEF-AES256-AES128, and PKCS12-DEF-AES256-AES128-GCM.
- The default type for the KeyStore.getInstance("PKCS12", "BC") can now be set using the org.bouncycastle.pkcs12.default system/security property.
- The PGP SExpParser will now handle Ed25519 and Ed448 keys.
- Dilithium and Kyber key encoding updated to latest Draft RFCs ([draft-ietf-lamps-dilithium-certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/) and [draft-ietf-lamps-kyber-certificates](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/))
- Support has been added for encryption key derivation using HKDF in CMS - see [draft-housley-lamps-cms-cek-hkdf-sha256](https://datatracker.ietf.org/doc/draft-housley-lamps-cms-cek-hkdf-sha256/).
- X500Name now recognises jurisdiction{C,ST,L} DNs.
- CertPathValidationContext and CertificatePoliciesValidation now include implementations of Memoable.
- The Composite post-quantum signatures implementation has been updated to the latest draft [draft-ounsworth-pq-composite-sigs](https://datatracker.ietf.org/doc/html/draft-ounsworth-pq-composite-sigs/).
- X509v2CRLBuilder now exposes setThisUpdate(Date), setThisUpdate(Date, Locale) and setThisUpdate(Time) overloads, mirroring the existing setNextUpdate methods so the thisUpdate field can be reset after the builder has been constructed (issue #1545).

### 2.12.4 Notes.

- Both versions of NTRUPrime have been updated to produce 256 bit secrets in line with Kyber. This should also bring them into line with other implementations such as those used in OpenSSH now.
- BCJSSE: The boolean system property 'org.bouncycastle.jsse.fips.allowRSAKeyExchange" now defaults to false. All RSA key exchange cipher suites will therefore be disabled when the BCJSSE provider is used in FIPS mode, unless this system property is explicitly set to true.
- OSGi compatibility should now be much improved.
- SignedMailValidator now includes a more general rollback method for locating the signature's trust anchor for use when the first approach fails.
- The PKCS12 store using GCM does not include the PKCS#12 MAC so no longer includes use of the PKCS#12 PBE scheme and only uses PBKDF2.
- In keeping with the current set of experimental OIDs for PQC algorithms, OIDs may have changed to reflect updated versions of the algorithms.

### 2.12.5 Security Advisories.

Release 1.78 deals with the following CVEs:

- CVE-2024-14041 - Possible timing based leakage of the private key in ML-KEM (Kyber) decapsulation due to non-constant time division in the message decoding and ciphertext compression functions ("KyberSlash").
- CVE-2024-29857 - Importing an EC certificate with specially crafted F2m parameters can cause high CPU usage during parameter evaluation.
- CVE-2024-30171 - Possible timing based leakage in RSA based handshakes due to exception processing eliminated.
- CVE-2024-30172 - Crafted signature and public key can be used to trigger an infinite loop in the Ed25519 verification code.
- CVE-2024-34447 - When endpoint identification is enabled in the BCJSSE and an SSL socket is not created with an explicit hostname (as happens with HttpsURLConnection), hostname verification could be performed against a DNS-resolved IP address. This has been fixed.

<a id="r1rv77"></a>

### 2.13.1 Version

Release: 1.77\
Date: 2023, November 13th

### 2.13.2 Defects Fixed

- Using an unescaped '=' in an X.500 RDN would result in the RDN being truncated silently. The issue is now detected and an exception is thrown.
- asn1.eac.CertificateBody was returning certificateEffectiveDate from getCertificateExpirationDate(). This has been fixed to return certificateExpirationDate.
- DTLS: Fixed retransmission in response to re-receipt of an aggregated ChangeCipherSpec.
- (D)TLS: Fixed compliance for supported_groups extension. Server will no longer negotiate an EC cipher suite using a default curve when the ClientHello includes the supported_groups extension but it contains no curves in common with the server. Similarly, a DH cipher suite will not be negotiated when the ClientHello includes supported_groups, containing at least one FFDHE group, but none in common with the server.
- IllegalStateException was being thrown by the Ed25519/Ed448 SignatureSpi. This has been fixed.
- TLS: class annotation issues that could occur between the BC provider and the TLS API for the GCMParameterSpec class when the jars were loaded on the boot class path have been addressed.
- Attempt to create an ASN.1 OID from a zero length byte array is now caught at construction time.
- Attempt to create an X.509 extension block which is empty will now be blocked cause an exception.
- IES implementation will now accept a null ParameterSpec if no nonce is needed.
- An internal method in Arrays was failing to construct its failure message correctly on an error. This has been fixed.
- HSSKeyPublicParameters.generateLMSContext() would fail for a unit depth key. This has been fixed.

### 2.13.3 Additional Features and Functionality

- BCJSSE: Added org.bouncycastle.jsse.client.omitSigAlgsCertExtension and org.bouncycastle.jsse.server.omitSigAlgsCertExtension boolean system properties to control (for client and server resp.) whether the signature_algorithms_cert extension should be omitted if it would be identical to signature_algorithms. Defaults to true, the historical behaviour.
- The low-level HPKE API now allows the sender to specify an ephemeral key pair.
- Support has been added for the delta-certificate requests in line with the current Chameleon Cert draft from the IETF.
- Some accommodation has been added for historical systems to accommodate variations in the SHA-1 digest OID for CMS SignedData.
- TLS: the TLS API will now try "RSAwithDigestAndMFG1" as well as the newer RSAPSS algorithm names when used with the JCA.
- TLS: RSA key exchange cipher suites are now disabled by default.
- Support has been added for PKCS#10 requests to allow certificates using the altSignature/altPublicKey extensions.

### 2.13.4 Notes.

- Kyber and Dilithium have been updated according to the latest draft of the standard. Dilithium-AES and Kyber-AES have now been removed. Kyber now produces 256 bit secrets for all parameter sets (in line with the draft standard).
- NTRU has been updated to produce 256 bit secrets in line with Kyber.
- SPHINCS+ can now be used to generate certificates in line with those used by (Open Quantum Safe) OQS.
- Falcon object identifiers are now in line with OQS as well.
- PQC CMS SignedData now defaults to SHA-256 for signed attributes rather than SHAKE-256. This is also a compatibility change, but may change further again as the IETF standard for CMS is updated.

<a id="r1rv76"></a>

### 2.14.1 Version

Release: 1.76\
Date: 2023, July 29th

### 2.14.2 Defects Fixed

- Service allocation in the provider could fail due to the lack of a permission block. This has been fixed.
- JceKeyFingerPrintCalculator has been generalised for different providers by using "SHA-256" for the algorithm string.
- BCJSSE: Fixed a regression in 1.74 (NullPointerException) that prevents a BCJSSE server from negotiating TLSv1.1 or earlier.
- DTLS: Fixed server support for client_certificate_type extension.
- Cipher.unwrap() for HQC could fail due to a miscalculation of the length of the KEM packet. This has been fixed.
- There was exposure to a Java 7 method in the Java 5 to Java 8 BCTLS jar which could cause issues with some TLS 1.2 cipher suites running on older JVMs. This is now fixed.

### 2.14.3 Additional Features and Functionality

- BCJSSE: Following OpenJDK, finalizers have been removed from SSLSocket subclasses. Applications should close sockets and not rely on garbage collection.
- BCJSSE: Added support for boolean system property "jdk.tls.client.useCompatibilityMode" (default "true").
- DTLS: Added server support for session resumption.
- JcaPKCS10CertificationRequest will now work with EC on the OpenJDK provider.
- TimeStamp generation now supports the SHA3 algorithm set.
- The SPHINCS+ simple parameters are now fully supported in the BCPQC provider.
- Kyber, Classic McEliece, HQC, and Bike now supported by the CRMF/CMS/CMP APIs.
- Builder classes have been add for PGP ASCII Armored streams allowing CRCs and versions to now be optional.
- An UnknownPacket type has been added to the PGP APIs to allow for forwards compatibility with upcoming revisions to the standard.

<a id="r1rv75"></a>

### 2.15.1 Version

Release: 1.75\
Date: 2023, June 21st

### 2.15.2 Defects Fixed

- Several Java 8 method calls were accidentally introduced in the Java 5 to Java 8 build. The affected classes have been refactored to remove this.
- (D)TLS: renegotiation after resumption now fixed to avoid breaking connection.

### 2.15.3 Notes.

- The ASN.1 core package has had some dead and retired methods cleaned up and removed.

<a id="r1rv74"></a>

### 2.16.1 Version

Release: 1.74\
Date: 2023, June 12th

### 2.16.2 Defects Fixed

- AsconEngine: Fixed a buffering bug when decrypting across multiple processBytes calls (ascon128a unaffected).
- Following the change to the wrapping of a single 64 bit block in 1.73, RFC3394WrapEngine.unwrap would reject 16 byte input produced by 1.72 or earlier with "checksum failed", as it applied only the single block decryption. The unwrap now falls back to the previous 6 pass form when the single block decryption does not yield the expected IV, so both the 1.73 and the pre-1.73 wrapped forms of an 8 byte key can be read. Wrapping continues to produce the single block form (issue #2079).
- Context based sanity checking on PGP signatures has been added.
- The ParallelHash clone constructor was not copying all fields. This is now fixed.
- The maximimum number of blocks for CTR/SIC modes was 1 block less than it should have been. This is now fixed.

### 2.16.3 Additional Features and Functionality

- The PGP API now supports wildcard key IDs for public key based data encryption.
- LMS now supports SHA256/192, SHAKE256/192, and SHAKE256/256 (the additional SP 8000-208 parameter sets).
- The PGP API now supports V5 and V6 AEAD encryption for encrypted data packets.
- The PGP examples have been updated to reflect key size and algorithm changes that have occurred since they were first written (10+ years...).
- (D)TLS: A new callback 'TlsPeer.notifyConnectionClosed' will be called when the connection is closed (including by failure).
- BCJSSE: Improved logging of connection events and include unique IDs in connection-specific log messages.
- BCJSSE: Server now logs the offered cipher suites when it fails to select one.
- BCJSSE: Added support for SSLParameters namedGroups and signatureSchemes properties (can also be used via BCJSSE extension API in earlier Java versions).
- DTLS: The initial handshake re-send time is now configurable by overriding 'TlsPeer.getHandshakeResendTimeMillis'.
- DTLS: Added support for connection IDs per RFC 9146.
- DTLS: Performance of DTLSVerifier has been improved so that it can reasonably be used for all incoming packets.
- Initial support has been added for [A Mechanism for Encoding Differences in Paired Certificates](https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/).
- The PGP API now supports parsing, encoding, and fingerprinting of V6 EC/EdEC keys.
- A thread safe verifier API has been added to the PGP API to support multi-threaded verification of certifications on keys and user IDs.
- The number of keys/sub-keys in a PGPKeyRing can now be found by calling PGPKeyRing.size().
- The PQC algorithms LMS/HSS, SPHINCS+, Dilithium, Falcon, and NTRU are now supported directly by the BC provider.

### 2.16.4 Notes.

- The now defunct PQC SIKE algorithm has been removed, this has also meant the removal of its resource files so the provider is now quite a bit smaller.
- As a precaution, HC128 now enforces a 128 bit IV, previous behaviour for shorter IVs can be supported where required by padding the IV to the 128 bits with zero.
- PGP encrypted data generation now uses integrity protection by default. Previous behaviour for encrypted data can be supported where required by calling PGPDataEncryptorBuilder.setWithIntegrityPacket(false) when data encryption is set up.
- There are now additional sanity checks in place to prevent accidental mis-use of PGPSignature objects. If this change causes any issues, you might want to check what your code is up to as there is probably a bug.

### 2.16.5 Security Advisories.

- CVE-2023-33201 - this release fixes an issue with the X509LDAPCertStoreSpi where a specially crafted certificate subject could be used to try and extract extra information out of an LDAP server with wild-card matching enabled.

<a id="r1rv73"></a>

### 2.17.1 Version

Release: 1.73\
Date: 2023, April 8th

### 2.17.2 Defects Fixed

- BCJSSE: Instantiating a JSSE provider in some contexts could cause an AccessControl exception. This has been fixed.
- The EC key pair generator can generate out of range private keys when used with SM2. A specific SM2KeyPairGenerator has been added to the low-level API and is used by KeyPairGenerator.getInstance("SM2", "BC"). The SM2 signer has been updated to check for out of range keys as well..
- The attached signature type byte was still present in Falcon signatures as well as the detached signature byte. This has been fixed.
- There was an off-by-one error in engineGetOutputSize() for ECIES. This has been fixed.
- The method for invoking read() internally in BCPGInputStream could result in inconsistent behaviour if the class was extended. This has been fixed.
- Fixed a rounding issue with FF1 Format Preserving Encryption algorithm for certain radices.
- Fixed RFC3394WrapEngine handling of 64 bit keys. RFC 3394 sec. 2 states "The only restriction the key wrap algorithm places on n is that n be at least two", the parenthetical going on to note that for key data of 64 bits or less the IV and the key data "form a single 128-bit codebook input making this key wrap unnecessary" - the case RFC 5649 sec. 4.1 spells out as a single ECB block encryption of IV || P. RFC3394WrapEngine previously ran the 6 pass algorithm with n = 1 for a single 64 bit block, which the specification does not define, and now emits the single block encryption instead. Note this changes the wrapped output for 8 byte input, for RFC3394WrapEngine and the AESWrapEngine, ARIAWrapEngine, CamelliaWrapEngine and SEEDWrapEngine built on it (the RFC 5649 padding engines - AESWrapPadEngine, ARIAWrapPadEngine - already handled the single block case themselves and are unaffected): 8 byte input wrapped by 1.73 or later cannot be unwrapped by 1.72 or earlier, and in 1.73 the reverse was also true (see the 1.74 note) (issue #2079).
- Internal buffer for blake2sp was too small and could result in an ArrayIndexOutOfBoundsException. This has been fixed.
- JCA PSS Signatures using SHAKE128 and SHAKE256 now support encoding of algorithm parameters.
- PKCS10CertificationRequest now checks for empty extension parameters.
- Parsing errors in the processing of PGP Armored Data now throw an explicit exception ArmoredInputException.
- PGP AEAD streams could occassionally be truncated. This has been fixed.
- The ESTService class now supports processing of chunked HTTP data.
- A constructed ASN.1 OCTET STRING with a single member would sometimes be re-encoded as a definite-length OCTET STRING. The encoding has been adjusted to preserve the BER status of the object.
- PKIXCertPathReviewer could fail if the trust anchor was also included in the certificate store being used for path analysis. This has been fixed.
- UTF-8 parsing of an array range ignored the provided length. This has been fixed.
- IPAddress has been written to provide stricter checking and avoid the use of Integer.parseInt().
- A Java 7 class snuck into the Java 5 to Java 8 build. This has been addressed.

### 2.17.3 Additional Features and Functionality

- The Rainbow NIST Post Quantum Round-3 Candidate has been added to the low-level API and the BCPQC provider (level 3 and level 5 parameter sets only).
- The GeMSS NIST Post Quantum Round-3 Candidate has been added to the low-level API.
- The org.bouncycastle.rsa.max_mr_tests property check has been added to allow capping of MR tests done on RSA moduli.
- Significant performance improvements in PQC algorithms, especially BIKE, CMCE, Frodo, HQC, Picnic.
- EdDSA verification now conforms to the recommendations of [Taming the many EdDSAs](https://ia.cr/2020/1244), in particular cofactored verification. As a side benefit, [Pornin's basis reduction](https://ia.cr/2020/454) is now used for EdDSA verification, giving a significant performance boost.
- Major performance improvements for Anomalous Binary (Koblitz) Curves.
- The lightweight Cryptography finalists Ascon, ISAP, Elephant, PhotonBeetle, Sparkle, and Xoodyak have been added to the light-weight cryptography API.
- BLAKE2bp and BLAKE2sp have been added to the light-weight cryptography API.
- Support has been added for X.509, Section 9.8, hybrid certificates and CRLs using alternate public keys and alternate signatures.
- The property "org.bouncycastle.emulate.oracle" has been added to signal the provider should return algorithm names on some algorithms in the same manner as the Oracle JCE provider.
- An extra replaceSigners method has been added to CMSSignedData which allows for specifying the digest algorithm IDs to be used in the new CMSSignedData object.
- Parsing and re-encoding of ASN.1 PEM data has been further optimized to prevent unecessary conversions between basic encoding, definite length, and DER.
- Support has been added for KEM ciphers in CMS in accordance with [draft-ietf-lamps-cms-kemri](https://www.ietf.org/id/draft-ietf-lamps-cms-kemri-00.html)
- Support has been added for certEncr in CRMF to allow issuing of certificates for KEM public keys.
- Further speedups have been made to CRC24.
- GCMParameterSpec constructor caching has been added to improve performance for JVMs that have the class available.
- The PGPEncrytedDataGenerator now supports injecting the session key to be used for PGP PBE encrypted data.
- The CRMF CertificateRequestMessageBuilder now supports optional attributes.
- Improvements to the s calculation in JPAKE.
- A general purpose PQCOtherInfoGenerator has been added which supports all Kyber and NTRU.
- An implementation of HPKE (RFC 9180 - Hybrid Public Key Encryption) has been added to the light-weight cryptography API.

### 2.17.4 Security Advisories.

- The PQC implementations have now been subject to formal review for secret leakage and side channels, there were issues in BIKE, Falcon, Frodo, HQC which have now been fixed. Some weak positives also showed up in Rainbow, Picnic, SIKE, and GeMSS - for now this last set has been ignored as the algorithms will either be updated if they reappear in the Signature Round, or deleted, as is already the case for SIKE (it is now in the legacy package). Details on the group responsible for the testing can be found in the [CONTRIBUTORS](../CONTRIBUTORS.md) file.
- For at least some ECIES variants (e.g. when using CBC) there is an issue with potential malleability of a nonce (implying silent malleability of the plaintext) that must be sent alongside the ciphertext but is outside the IES integrity check. For this reason the automatic generation of nonces with IED is now disabled and they have to be passed in using an IESParameterSpec. The current advice is to agree on a nonce between parties and then rely on the use of the ephemeral key component to allow the nonce (rather the so called nonce) usage to be extended.

### 2.17.5 Notes.

- Most test data files have now been migrated to a separate project bc-test-data which is also available on github. If you clone bc-test-data at the same level as the bc-java project the tests will find the test data they require.
- There has been further work to make entropy collection more friendly in container environments. See [DRBG.java](https://github.com/bcgit/bc-java/blob/main/prov/src/main/java/org/bouncycastle/jcajce/provider/drbg/DRBG.java) for details. We would welcome any further feedback on this as we clearly cannot try all situations first hand.

<a id="r1rv72.3"></a>

### 2.18.1 Version

Release: <a id="r1rv72.2">1.72.2</a>, 1.72.3\
Date: 2022, November 20th

### 2.18.2 Defects Fixed

- PGP patch release - fix for OSGI and version header in 1.72.1 jar file.

<a id="r1rv72.1"></a>

### 2.19.1 Version

Release: 1.72.1\
Date: 2022, October 25th

### 2.19.2 Defects Fixed

- PGP patch release - fix for regression in OpenPGP PGPEncryptedData.java which could result in checksum failures on correct files.

<a id="r1rv72"></a>

### 2.20.1 Version

Release: 1.72\
Date: 2022, September 25th

### 2.20.2 Defects Fixed

- There were parameter errors in XMSS^MT OIDs for XMSSMT_SHA2_40/4_256 and XMSSMT_SHA2_60/3_256. These have been fixed.
- There was an error in Merkle tree construction for the Evidence Records (ERS) implementation which could result in invalid roots been timestamped. ERS now produces an ArchiveTimeStamp for each data object/group with an associated reduced hash tree. The reduced hash tree is now calculated as a simple path to the root of the tree for each record.
- OpenPGP will now ignore signatures marked as non-exportable on encoding.
- A tagging calculation error in GCMSIV which could result in incorrect tags has been fixed.
- Issues around Java 17 which could result in failing tests have been addressed.

### 2.20.3 Additional Features and Functionality

- BCJSSE: TLS 1.3 is now enabled by default where no explicit protocols are supplied (e.g. "TLS" or "Default" SSLContext algorithms, or SSLContext.getDefault() method).
- BCJSSE: Rewrite SSLEngine implementation to improve compatibility with SunJSSE.
- BCJSSE: Support export of keying material via extension API.
- (D)TLS: Add support for 'tls-exporter' channel binding per RFC 9266.
- (D)TLS (low-level API): By default, only (D)TLS 1.2 and TLS 1.3 are offered now. Earlier versions are still supported if explicitly enabled. Users may need to check they are offering suitable cipher suites for TLS 1.3.
- (D)TLS (low-level API): Add support for raw public keys per RFC 7250.
- CryptoServicesRegistrar now has a setServicesConstraints() method on it which can be used to selectively turn off algorithms.
- The NIST PQC Alternate Candidate, Picnic, has been added to the low level API and the BCPQC provider.
- SPHINCS+ has been upgraded to the latest submission, SPHINCS+ 3.1 and support for Haraka has been added.
- Evidence records now support timestamp renewal and hash renewal.
- The SIKE Alternative Candidate NIST Post Quantum Algorithm has been added to the low-level API and the BCPQC provider.
- The NTRU Round 3 Finalist Candidate NIST Post Quantum Algorithm has been added to the low-level API and the BCPQC provider.
- The Falcon Finalist NIST Post Quantum Algorithm has been added to the low-level API and the BCPQC provider.
- The CRYSTALS-Kyber Finalist NIST Post Quantum Algorithm has been added to the low-level API and the BCPQC provider.
- Argon2 Support has been added to the OpenPGP API.
- XDH IES has now been added to the BC provider.
- The OpenPGP API now supports AEAD encryption and decryption.
- The NTRU Prime Alternative Candidate NIST Post Quantum Algorithms have been added to the low-level API and the BCPQC provider.
- The CRYSTALS-Dilithium Finalist NIST Post Quantum Algorithm has been added to the low-level API and the BCPQC provider.
- The BIKE NIST Post Quantum Alternative/Round-4 Candidate has been added to the low-level API and the BCPQC provider.
- The HQC NIST Post Quantum Alternative/Round-4 Candidate has been added to the low-level API and the BCPQC provider.
- Grain128AEAD has been added to the lightweight API.
- A fast version of CRC24 has been added for use with the PGP API.
- Some additional methods and fields have been exposed in the PGPOnePassSignature class to (hopefully) make it easier to deal with nested signatures.
- CMP support classes have been updated to reflect the latest editions to the the draft RFC "Lightweight Certificate Management Protocol (CMP) Profile".
- Support has been added to the PKCS#12 implementation for the Oracle trusted certificate attribute.
- Performance of our BZIP2 classes has been improved.

### 2.20.4 Notes

Keep in mind the PQC algorithms are still under development and we are still at least a year and a half away from published standards. This means the algorithms may still change so by all means experiment, but do not use the PQC algoritms for anything long term.

The legacy "Rainbow" and "McEliece" implementations have been removed from the BCPQC provider. The underlying classes are still present if required. Other legacy algorithm implementations can be found under the org.bouncycastle.pqc.legacy package.

### 2.20.5 Security Notes

The PQC SIKE algorithm is provided for research purposes only. It should now be regarded as broken. The SIKE implementation will be withdrawn in BC 1.73.

<a id="r1rv71"></a>

### 2.21.1 Version

Release: 1.71\
Date: 2022, March 31st.

### 2.21.2 Defects Fixed

- In line with GPG the PGP API now attempts to preserve comments containing non-ascii UTF-8 characters.
- An accidental partial dependency on Java 1.7 has been removed from the TLS API.
- JcaPKIXIdentityBuilder would fail to process File objects correctly. This is now fixed.
- Some byte[] parameters to the CMP API were not being defensively cloned to prevent accidental changes. Extra defensive cloning has been added.
- CMS primitives would sometimes convert ASN.1 definite-length encodings into indefinite-length encodings. The primitives will now try and preserve the original encoding where possible.
- CMSSignedData.getAttributeCertificates() now properly restricts the tag values checked to just 1 (the obsolete v1 tag) and 2 (for the more current v2 certificates).
- BCJSSE now tries to validate a custom KeyManager selection in order to catch errors around a key manager ignoring key type early.
- Compressed streams in PGP ending with zero length partial packets could cause failure on parsing the OpenPGP API. This has been fixed.
- The fallback mode for JceAsymmetricKeyWrapper/Unwrapper would lose track of any algorithm parameters generated in the initial attempt. The algorithm parameters are now propagated.
- An accidental regression introduced by a fix for another issue in PKIXCertPathReviewer around use of the AuthorityKeyIdentifier extension and it failing to match a certificate uniquely when the serial number field is missing has been fixed.
- An error was found in the creation of TLS 1.3 Export Keying Material which could cause compatibility issues. This has been fixed.

### 2.21.3 Additional Features and Functionality

- Support has been added for OpenPGP regular expression signature packets.
- Support has been added for OpenPGP PolicyURI signature packets.
- A utility method has been added to PGPSecretKeyRing to allow for inserting or replacing a PGPPublicKey.
- A utility method has been added to PGPSecretKeyRing to allow for inserting or replacing a PGPPublicKey.
- The NIST PQC Finalist, Classic McEliece has been added to the low level API and the BCPQC provider.
- The NIST PQC Alternate Candidate, SPHINCS+ has been added to the BCPQC provider.
- The NIST PQC Alternate Candidate, FrodoKEM has been added to the low level API and the BCPQC provider.
- The NIST PQC Finalist, SABER has been added to the low level API and the BCPQC provider.
- KMAC128, KMAC256 has been added to the BC provider (empty customization string).
- TupleHash128, TupleHash256 has been added to the BC provider (empty customization string).
- ParallelHash128, ParallelHash256 has been added to the BC provider (empty customization string, block size 1024 bits).
- Two new properties: "org.bouncycastle.rsa.max_size" (default 15360) and "org.bouncycastle.ec.fp_max_size" (default 1042) have been added to cap the maximum size of RSA and EC keys.
- RSA modulus are now checked to be provably composite using the enhanced MR probable prime test.
- Imported EC Fp basis values are now validated against the MR prime number test before use. The certainty level of the prime test can be determined by "org.bouncycastle.ec.fp_certainty" (default 100).
- The BC entropy thread now has a specific name: "BC-ENTROPY-GATHERER".
- Utility methods have been added for joining/merging PGP public keys and signatures.
- Blake3-256 has been added to the BC provider.
- DTLS: optimisation to delayed handshake hash.
- Further additions to the ETSI 102 941 support in the ETSI/ITS package: certification request, signed message generation and verification now supported.
- CMSSignedDataGenerator now supports the direct generation of definite-length data.
- The NetscapeCertType class now has a hasUsages() method on it for querying usage settings on its bit string.
- Support for additional input has been added for deterministic (EC)DSA.
- The OpenPGP API provides better support for subkey generation.
- BCJSSE: Added boolean system properties "org.bouncycastle.jsse.client.dh.disableDefaultSuites" and "org.bouncycastle.jsse.server.dh.disableDefaultSuites". Default "false". Set to "true" to disable inclusion of DH cipher suites in the default cipher suites for client/server respectively.
- ASN.1 object support has been added for the Lightweight Certificate Management Protocol (CMP), currently in draft.
- A HybridValueParamterSpec class has been added for use with KeyAgreement to support SP 800-56C hybrid (so classical/post-quantum) key agreement.

### 2.21.4 Notes

- The deprecated QTESLA implementation has been removed from the BCPQC provider.
- The [submission update to SPHINCS+](https://groups.google.com/u/1/a/list.nist.gov/g/pqc-forum/c/F9ZUtWCij54) has been added. This changes the generation of signatures - particularly deterministic ones.

<a id="r1rv70"></a>

### 2.22.1 Version

Release: 1.70\
Date: 2021, November 29th.

### 2.22.2 Defects Fixed

- Blake 3 output limit is enforced.
- The PKCS12 KeyStore was relying on default precedence for its key Cipher implementation so was sometimes failing if used from the keytool. The KeyStore class now makes sure it uses the correct Cipher implementation.
- Fixed bzip2 compression for empty contents (GH #993).
- ASN.1: More robust handling of high tag numbers and definite-length forms.
- BCJSSE: Fix a concurrent modification issue in session contexts (GH#968).
- BCJSSE: Don't log sensitive system property values (GH#976).
- BCJSSE: Fixed a priority issue amongst imperfect-match credentials in KeyManager classes.
- The IES AlgorithmParameters object has been re-written to properly support all the variations of IESParameterSpec.
- getOutputSize() for ECIES has been corrected to avoid occassional underestimates.
- The lack of close() in the ASN.1 Dump command line utility was triggering false positives in some code analysis tools. A close() call has been added.
- PGPPublicKey.getBitStrength() now properly recognises EdDSA keys.

### 2.22.3 Additional Features and Functionality

- Missing PGP CRC checksums can now be optionally ignored using setDetectMissingCRC() (default false) on ArmoredInputStream.
- PGPSecretKey.copyWithNewPassword() now has a variant which uses USAGE_SHA1 for key protection if a PGPDigestCalculator is passed in.
- PGP ASCII armored data now skips "\t", "\v", and "\f".
- PKCS12 files with duplicate localKeyId attributes on certificates will now have the incorrect attributes filtered out, rather than the duplicate causing an exception.
- PGPObjectFactory will now ignore packets representing unrecognised signature versions in the input stream.
- The X.509 extension generator will now accumulate some duplicate X.509 extensions into a single extension where it is possible to do so.
- Removed support for maxXofLen in Kangaroo digest.
- Ignore marker packets in PGP Public and Secret key ring collection.
- An implementation of LEA has been added to the low-level API.
- Access, recovery, and direct use for PGP session keys has been added to the OpenPGP API for processing encrypted data.
- A PGPCanonicalizedDataGenerator has been added which converts input into canonicalized literal data for text and UTF-8 mode.
- A getUserKeyingMaterial() method has been added to the KeyAgreeRecipientInformation class.
- ASN.1: Tagged objects (and parsers) now support all tag classes. Special code for ApplicationSpecific has been deprecated and re-implemented in terms of TaggedObject.
- ASN.1: Improved support for nested tagging.
- ASN.1: Added support for GraphicString, ObjectDescriptor, RelativeOID.
- ASN.1: Added support for constructed BitString encodings, including efficient parsing for large values.
- TLS: Added support for external PSK handshakes.
- TLS: Check policy restrictions on key size when determining cipher suite support.
- A performance issue in KeccakDigest due to left over debug code has been identified and dealt with.
- BKS key stores can now be used for collecting protected keys (note: any attempt to store such a store will cause an exception).
- A method for recovering user keying material has been added to KeyAgreeRecipientInformation.
- Support has been added to the CMS API for SHA-3 based PLAIN-ECDSA.
- The low level BcDefaultDigestProvider now supports the SHAKE family of algorithms and the SM3 alogirthm.
- PGPKeyRingGenerator now supports creation of key-rings with direct-key identified keys.
- The PQC NIST candidate, signature algorithm SPHINCS+ has been added to the low-level API.
- ArmoredInputStream now explicitly checks for a '\n' if in crLF mode.
- Direct support for NotationDataOccurances, Exportable, Revocable, IntendedRecipientFingerPrints, and AEAD algorithm preferences has been added to PGPSignatureSubpacketVector.
- Further support has been added for keys described using S-Expressions in GPG 2.2.X.
- Support for OpenPGP Session Keys from the (draft) Stateless OpenPGP CLI has been added.
- Additional checks have been added for PGP marker packets in the parsing of PGP objects.
- A CMSSignedData.addDigestAlgorithm() has been added to allow for adding additional digest algorithm identifiers to CMS SignedData structures when required.
- Support has been added to CMS for the LMS/HSS signature algorithm.
- The system property "org.bouncycastle.jsse.client.assumeOriginalHostName" (default false) has been added for dealing with SNI problems related to the host name not being propagate by the JVM.
- The JcePKCSPBEOutputEncryptorBuilder now supports SCRYPT with ciphers that do not have algorithm parameters (e.g. AESKWP).
- Support is now added for certificates using ETSI TS 103 097, "Intelligent Transport Systems (ITS)" in the bcpkix package.

### 2.22.4 Notes.

- While this release should maintain source code compatibility, developers making use of some parts of the ASN.1 library will find that some classes need recompiling. Apologies for the inconvenience.

<a id="r1rv69"></a>

### 2.23.1 Version

Release: 1.69\
Date: 2021, June 7th.

### 2.23.2 Defects Fixed

- Lightweight and JCA conversion of Ed25519 keys in the PGP API could drop the leading byte as it was zero. This has been fixed.
- Marker packets appearing at the start of PGP public key rings could cause parsing failure. This has been fixed.
- ESTService could fail for some valid Content-Type headers. This has been fixed.
- Originator key algorithm parameters were being passed as NULL in key agreement recipients. The parameters now reflect the value of the parameters in the key's SubjectPublicKeyInfo.
- ContentType on encapsulated data was not been passed through correctly for authenticated and enveloped data. This has been fixed.
- NTRUEncryptionParameters and NTRUEncryptionKeyGenerationParameters were not correctly cloning the contained message digest. This has been fixed.
- CertificateFactory.generateCertificates()/generateCRLs() would throw an exception if extra data was found at the end of a PEM file even if valid objects had been found. Extra data is now ignored providing at least one object found.
- Internal class PKIXCRLUtil could throw a NullPointerException for CRLs with an absent nextUpdate field. This has been fixed.
- PGP ArmoredInputStream now fails earlier on malformed headers.
- The McElieceKobaraImaiCipher was randomly throwing "Bad Padding: invalid ciphertext" exception while decrypting due to leading zeroes been missed during processing of the cipher text. This has been fixed.
- Ed25519 keys being passed in via OpenSSH key spec are now validated in the KeyFactory.
- Blowfish keys are now range checked on cipher construction.
- In some cases PGPSecretKeyRing was failing to search its extraPubKeys list when searching for public keys.
- The BasicConstraintsValidation class in the BC cert path validation tools has improved conformance to RFC 5280.
- AlgorithmIdentifiers involving message digests now attempt to follow the latest conventions for the parameters field (basically DER NULL appears less).
- Fix various conversions and interoperability for XDH and EdDSA between BC and SunEC providers.
- TLS: Prevent attempts to use KeyUpdate mechanism in versions before TLS 1.3.

### 2.23.3 Additional Features and Functionality

- GCM-SIV has been added to the lightweight API and the provider.

- Blake3 has been added to the lightweight API.

- The OpenSSL PEMParser can now be extended to add specialised parsers.

- Base32 encoding has now been added, the default alphabet is from RFC 4648.

- The KangarooTwelve message digest has been added to the lightweight API.

- An implementation of the two FPE algorithms, FF1 and FF3-1 in SP 800-38G has been added to the lightweight API and the JCE provider.

- An implementation of ParallelHash has been added to the lightweight API.

- An implementation of TupleHash has been added to the lightweight API.

- RSA-PSS now supports the use of SHAKE128 and SHAKE256 as the mask generation function and digest.

- ECDSA now supports the use of SHAKE128 and SHAKE256.

- PGPPBEEncryptedData will now reset the stream if the initial checksum fails so another password can be tried.

- Iterators on public and secret key ring collections in PGP now reflect the original order of the public/secret key rings they contain.

- KeyAgreeRecipientInformation now has a getOriginator() method for retrieving the underlying orginator information.

- PGPSignature now has a getDigestPrefix() method for people wanting exposure to the signature finger print details.

- The old BKS-V1 format keystore is now disabled by default. If you need to use BKS-V1 for legacy reasons, it can be re-enabled by adding:

      org.bouncycastle.bks.enable_v1=true

  to the java.security file. We would be interested in hearing from anyone that needs to do this.

- PLAIN-ECDSA now supports the SHA3 digests.

- Some highlevel support for RFC 4998 ERS has been added for ArchiveTimeStamp and EvidenceRecord. The new classes are in the org.bouncycastle.tsp.ers package.

- ECIES has now also support SHA256, SHA384, and SHA512.

- digestAlgorithms filed in CMS SignedData now includes counter signature digest algorithms where possible.

- A new property "org.bouncycastle.jsse.config" has been added which can be used to configure the BCJSSE provider when it is created using the no-args constructor.

- In line with changes in OpenSSL 1.1.0, OpenSSLPBEParametersGenerator can now be configured with a digest.

- PGPKeyRingGenerator now includes a method for adding a subkey with a primary key binding signature.

- Support for ASN.1 PRIVATE tags has been added.

- Performance enhancements to Nokeon, AES, GCM, and SICBlockCipher.

- Support for ecoding/decoding McElieceCCA2 keys has been added to the PQC API

- BCJSSE: Added support for jdk.tls.maxCertificateChainLength system property (default is 10).

- BCJSSE: Added support for jdk.tls.maxHandshakeMessageSize system property (default is 32768).

- BCJSSE: Added support for jdk.tls.client.enableCAExtension (default is 'false').

- BCJSSE: Added support for jdk.tls.client.cipherSuites system property.

- BCJSSE: Added support for jdk.tls.server.cipherSuites system property.

- BCJSSE: Extended ALPN support via standard JSSE API to JDK 8 versions after u251/u252.

- BCJSSE: Key managers now support EC credentials for use with TLS 1.3 ECDSA signature schemes (including brainpool).

- TLS: Add TLS 1.3 support for brainpool curves per RFC 8734.

### 2.23.4 Notes

- There is a small API change in the PKIX package to the DigestAlgorithmIdentifierFinder interface as a find() method that takes an ASN1ObjectIdentifier has been added to it. For people wishing to extend their own implementations, see DefaultDigestAlgorithmIdentifierFinder for a sample implementation.
- A version of the bcmail API supporting Jakarta Mail has now been added (see bcjmail jar).
- Some work has been done on moving out code that does not need to be in the provider jar. This has reduced the size of the provider jar and should also make it easier for developers to patch the classes involved as they no longer need to be signed. bcpkix and bctls are both dependent on the new bcutil jar.

<a id="r1rv68"></a>

### 2.24.1 Version

Release: 1.68\
Date: 2020, December 21st.

### 2.24.2 Defects Fixed

- Some BigIntegers utility methods would fail for BigInteger.ZERO. This has been fixed.
- PGPUtil.isKeyRing() was not detecting secret sub-keys in its input. This has been fixed.
- The ASN.1 class, ArchiveTimeStamp was insisting on a value for the optional reducedHashTree field. This has been fixed.
- BCJSSE: Lock against multiple writers - a possible synchronization issue has been removed.

### 2.24.3 Additional Features and Functionality

- BCJSSE: Added support for system property com.sun.net.ssl.requireCloseNotify. Note that we are using a default value of 'true'.
- BCJSSE: 'TLSv1.3' is now a supported protocol for both client and server. For this release it is only enabled by default for the 'TLSv1.3' SSLContext, but can be explicitly enabled using 'setEnabledProtocols' on an SSLSocket or SSLEngine, or via SSLParameters.
- BCJSSE: Session resumption is now also supported for servers in TLS 1.2 and earlier. For this release it is disabled by default, and can be enabled by setting the boolean system property org.bouncycastle.jsse.server.enableSessionResumption to 'true'.
- The provider RSA-PSS signature names that follow the JCA naming convention.
- FIPS mode for the BCJSSE now enforces namedCurves for any presented certificates.
- PGPSignatureSubpacketGenerator now supports editing of a pre-existing sub-packet list.

<a id="r1rv67"></a>

### 2.25.1 Version

Release: 1.67\
Date: 2020, November 1st.

### 2.25.2 Defects Fixed

- BCJSSE: SunJSSE compatibility fix - override of getChannel() removed and 'urgent data' behaviour should now conform to what the SunJSSE expects.
- Nested BER data could sometimes cause issues in octet strings. This has been fixed.
- Certificates/CRLs with short signatures could cause an exception in toString() in the BC X509 Certificate implmentation. This has been fixed.
- In line with latest changes in the JVM, SignatureSpis which don't require parameters now return null on engineGetParameters().
- The RSA KeyFactory now always preferentially produces RSAPrivateCrtKey where it can on requests for a KeySpec based on an RSAPrivateKey.
- CMSTypedStream\$FullReaderStream now handles zero length reads correctly.
- Unecessary padding was added on KMAC when the key length was block aligned. This has been fixed.
- Zero length data would cause an unexpected exception from RFC5649WrapEngine. This has been fixed.
- OpenBSDBcrypt was failing to handle some valid prefixes. This has been fixed.

### 2.25.3 Additional Features and Functionality

- Performance of Argon2 has been improved.
- Performance of Noekeon has been improved.
- A setSessionKeyObfuscation() method has been added to PublicKeyKeyEncryptionMethodGenerator to allow turning off of session key obfuscation (default is on, method primarily to get around early version GPG issues with AES-128 keys).
- Implemented 'safegcd' constant-time modular inversion (as well as a variable-time variant). It has replaced Fermat inversion in all our EC code, and BigInteger.modInverse in several other places, particularly signers. This improves side-channel protection, and also gives a significant performance boost.
- Performance of custom binary ECC curves and Edwards Curves has been improved.
- BCJSSE: New boolean system property 'org.bouncycastle.jsse.keyManager.checkEKU' allows to disable ExtendedKeyUsage restrictions when selecting credentials (although the peer may still complain).
- Initial support has been added for "Composite Keys and Signatures For Use In Internet PKI" using the test OID. Please note there will be further refinements to this as the draft is standardised.
- The BC EdDSA signature API now supports keys implementing all methods on the EdECKey and XECKey interfaces directly.
- Work has begun on classes to support the ETSI TS 103 097, Intelligent Transport Systems (ITS) in the bcpkix package.
- Further optimization work has been done on GCM.
- A NewHope based processor, similar to the one for Key Agreement has been added for trying to "quantum hard" KEM algorithms.
- PGP clear signed signatures now support SHA-224.
- Treating absent vs NULL as equivalent can now be configured by a system property. By default this is not enabled.
- Mode name checks in Cipher strings should now make sure an improper mode name always results in a NoSuchAlgorithmException.
- In line with changes in OpenSSL, the OpenSSLPBKDF now uses UTF-8 encoding.

### 2.25.4 Security Advisory

- As described in CVE-2020-28052, the OpenBSDBCrypt.checkPassword() method had a flaw in it due to a change for BC 1.65. BC 1.66 is also affected. The issue is fixed in BC 1.67. If you are using OpenBSDBCrypt.checkPassword() and you are using BC 1.65 or BC 1.66 we strongly advise moving to BC 1.67 or later.

<a id="r1rv66"></a>

### 2.26.1 Version

Release: 1.66\
Date: 2020, July 4th.

### 2.26.2 Defects Fixed

- EdDSA verifiers now reset correctly after rejecting overly long signatures.
- BCJSSE: SSLSession.getPeerCertificateChain could throw NullPointerException. This has been fixed.
- qTESLA-I verifier would reject some valid signatures. This has been fixed.
- qTESLA verifiers now reject overly long signatures.
- PGP regression caused failure to preserve existing version header when headers were reset. This has now been fixed.
- PKIXNameConstraintValidator had a bad cast preventing use of multiple OtherName constraints. This has been fixed.
- Serialisation of the non-CRT RSA Private Key could cause a NullPointerException. This has been fixed.
- An extra 4 bytes was included in the start of HSS public key encodings. This has been fixed.
- CMS with Ed448 using a direct signature was using id-shake256-len rather than id-shake256. This has been fixed.
- Use of GCMParameterSpec could cause an AccessControlException under some circumstances. This has been fixed.
- DTLS: Fixed high-latency HelloVerifyRequest handshakes.
- An encoding bug for rightEncoded() in KMAC has been fixed.
- For a few values the cSHAKE implementation would add unnecessary pad bytes where the N and S strings produced encoded data that was block aligned. This has been fixed.
- There were a few circumstances where Argon2BytesGenerator might hit an unexpected null. These have been removed.

### 2.26.3 Additional Features and Functionality

- The qTESLA signature algorithm has been updated to v2.8 (20191108).
- BCJSSE: Client-side OCSP stapling now supports status_request_v2 extension.
- Support has been added for PKIXRevocationChecker for users of Java 8 and later.
- Support has been added for "ocsp.enable", "ocsp.responderURL" for users of Java 8 and later.
- Support has been added for "org.bouncycastle.x509.enableCRLDP" to the PKIX validator.
- BCJSSE: Now supports system property 'jsse.enableFFDHE'
- BCJSSE: Now supports system properties 'jdk.tls.client.SignatureSchemes' and 'jdk.tls.server.SignatureSchemes'.
- Multi-release support has been added for Java 11 XECKeys.
- Multi-release support has been added for Java 15 EdECKeys.
- The MiscPEMGenerator will now output general PrivateKeyInfo structures.
- A new property "org.bouncycastle.pkcs8.v1_info_only" has been added to make the provider only produce version 1 PKCS8 PrivateKeyInfo structures.
- The PKIX CertPathBuilder will now take the target certificate from the target constraints if a specific certificate is given to the selector.
- BCJSSE: A range of ARIA and CAMELLIA cipher suites added to supported list.
- BCJSSE: Now supports the PSS signature schemes from RFC 8446 (TLS 1.2 onwards).
- Performance of the Base64 encoder has been improved.
- The PGPPublicKey class will now include direct key sigantures when checking for key expiry times.

### 2.26.4 Notes

The qTESLA update breaks compatibility with previous versions. Private keys now include a hash of the public key at the end, and signatures are no longer interoperable with previous versions.

<a id="r1rv65"></a>

### 2.27.1 Version

Release: 1.65\
Date: 2020, March 31st.

### 2.27.2 Defects Fixed

- DLExternal would encode using DER encoding for tagged SETs. This has been fixed.
- ChaCha20Poly1305 could fail for large (\>~2GB) files. This has been fixed.
- ChaCha20Poly1305 could fail for small updates when used via the provider. This has been fixed.
- Properties.getPropertyValue could ignore system property when other local overrides set. This has been fixed.
- The entropy gathering thread was not running in daemon mode, meaning there could be a delay in an application shutting down due to it. This has been fixed.
- A recent change in Java 11 could cause an exception with the BC Provider's implementation of PSS. This has been fixed.
- BCJSSE: TrustManager now tolerates having no trusted certificates.
- BCJSSE: Choice of credentials and signing algorithm now respect the peer's signature_algorithms extension properly.
- BCJSSE: KeyManager for KeyStoreBuilderParameters no longer leaks memory.

### 2.27.3 Additional Features and Functionality

- LMS and HSS (RFC 8554) support has been added to the low level library and the PQC provider.
- SipHash128 support has been added to the low level library and the JCE provider.
- BCJSSE: BC API now supports explicitly specifying the session to resume.
- BCJSSE: Ed25519, Ed448 are now supported when TLS 1.2 or higher is negotiated (except in FIPS mode).
- BCJSSE: Added support for extended_master_secret system properties: jdk.tls.allowLegacyMasterSecret, jdk.tls.allowLegacyResumption, jdk.tls.useExtendedMasterSecret .
- BCJSSE: KeyManager and TrustManager now check algorithm constraints for keys and certificate chains.
- BCJSSE: KeyManager selection of server credentials now prefers matching SNI hostname (if any).
- BCJSSE: KeyManager may now fallback to imperfect credentials (expired, SNI mismatch).
- BCJSSE: Client-side OCSP stapling support (beta version: via status_request extension only, provides jdk.tls.client.enableStatusRequestExtension, and requires CertPathBuilder support).
- TLS: DSA in JcaTlsCrypto now falls back to stream signing to work around NoneWithDSA limitations in default provider.

<a id="r1rv64"></a>

### 2.28.1 Version

Release: 1.64\
Date: 2019, October 7th.

### 2.28.2 Defects Fixed

- OpenSSH: Fixed padding in generated Ed25519 private keys.
- Validation of headers in PemReader now looks for tailing dashes in header.
- PKIXNameConstraintValidator was throwing a NullPointerException on OtherName. This has been fixed.
- Some compatibility issues around the signature encryption algorithm field in CMS SignedData and the GOST algorithms have been addressed.
- GOST3410-2012-512 now uses the GOST3411-2012-256 as its KDF digest.

### 2.28.3 Additional Features and Functionality

- PKCS12: key stores containing only certificates can now be created without the need to provide passwords.
- BCJSSE: Initial support for AlgorithmConstraints; protocol versions and cipher suites.
- BCJSSE: Initial support for 'jdk.tls.disabledAlgorithms'; protocol versions and cipher suites.
- BCJSSE: Add SecurityManager check to access session context.
- BCJSSE: Improved SunJSSE compatibility of the NULL_SESSION.
- BCJSSE: SSLContext algorithms updated for SunJSSE compatibility (default enabled protocols).
- The digest functions Haraka-256 and Haraka-512 have been added to the provider and the light-weight API
- XMSS/XMSS^MT key management now allows for allocating subsets of the private key space using the extraKeyShard() method. Use of StateAwareSignature is now deprecated.
- Support for Java 11's NamedParameterSpec class has been added (using reflection) to the EC and EdEC KeyPairGenerator implementations.

### 2.28.4 Removed Features and Functionality

- Deprecated ECPoint 'withCompression' tracking has been removed.

### 2.28.5 Security Advisory

- A change to the ASN.1 parser in 1.63 introduced a regression that can cause an OutOfMemoryError to occur on parsing ASN.1 data. We recommend upgrading to 1.64, particularly where an application might be parsing untrusted ASN.1 data from third parties.

<a id="r1rv63"></a>

### 2.29.1 Version

Release: 1.63\
Date: 2019, September 10th.

### 2.29.2 Defects Fixed

- The ASN.1 parser would throw a large object exception for some objects which could be safely parsed. This has been fixed.
- GOST3412-2015 CTR mode was unusable at the JCE level. This has been fixed.
- The DSTU MACs were failing to reset fully on doFinal(). This has been fixed.
- The DSTU MACs would throw an exception if the key was a multiple of the size as the MAC's underlying buffer size. This has been fixed.
- EdEC and QTESLA were not previously usable with the post Java 9 module structure. This is now fixed.
- ECNR was not correctly bounds checking the input and could produce invalid signatures. This is now fixed.
- ASN.1: Enforce no leading zeroes in OID branches (longer than 1 character).
- TLS: Fix X448 support in JcaTlsCrypto.
- Fixed field reduction for secp128r1 custom curve.
- Fixed unsigned multiplications in X448 field squaring.
- Some issues over subset Name Constraint validation in the CertPath analyser have now been fixed.
- TimeStampResponse.getEncoded() could throw an exception if the TimeStampToken was null. This has been fixed.
- Unnecessary memory usage in the ARGON2 implementation has been removed.
- Param-Z in the GOST-28147 algorithm was not resolving correctly. This has been fixed.
- It is now possible to specify different S-Box parameters for the GOST 28147-89 MAC.

### 2.29.3 Additional Features and Functionality

- QTESLA is now updated with the round 2 changes. Note: the security catergories, and in some cases key generation and signatures, have changed. For people interested in comparison, the round 1 version is now moved to org.bouncycastle.pqc.crypto.qteslarnd1 - this package will be deleted in 1.64. Please keep in mind that QTESLA may continue to evolve.
- Support has been added for generating Ed25519/Ed448 signed certificates.
- A method for recovering the message/digest value from an ECNR signature has been added.
- Support for the ZUC-128 and ZUC-256 ciphers and MACs has been added to the provider and the lightweight API.
- Support has been added for ChaCha20-Poly1305 AEAD mode from RFC 7539.
- Improved performance for multiple ECDSA verifications using same public key.
- Support for PBKDF2withHmacSM3 has been added to the BC provider.
- The S/MIME API has been fixed to avoid unnecessary delays due to DNS resolution of a hosts name in internal MimeMessage preparation.
- The valid path for EST services has been updated to cope with the characters used in the Aruba clearpass EST implementation.

<a id="r1rv62"></a>

### 2.30.1 Version

Release: 1.62\
Date: 2019, June 3rd.

### 2.30.2 Defects Fixed

- DTLS: Fixed infinite loop on IO exceptions.
- DTLS: Retransmission timers now properly apply to flights monolithically.
- BCJSSE: setEnabledCipherSuites ignores unsupported cipher suites.
- BCJSSE: SSLSocket implementations store passed-in 'host' before connecting.
- BCJSSE: Handle SSLEngine closure prior to handshake.
- BCJSSE: Provider now configurable using security config under Java 11 and later.
- EdDSA verifiers now reject overly long signatures.
- XMSS/XMSS^MT OIDs now using the values defined in RFC 8391.
- XMSS/XMSS^MT keys now encoded with OID at start.
- An error causing valid paths to be rejected due to DN based name constraints has been fixed in the CertPath API.
- Name constraint resolution now includes special handling of serial numbers.
- Cipher implementations now handle ByteBuffer usage where the ByteBuffer has no backing array.
- CertificateFactory now enforces presence of PEM headers when required.
- A performance issue with RSA key pair generation that was introduced in 1.61 has been mostly eliminated.

### 2.30.3 Additional Features and Functionality

- Builders for X509 certificates and CRLs now support replace and remove extension methods.
- DTLS: Added server-side support for HelloVerifyRequest.
- DTLS: Added support for an overall handshake timeout.
- DTLS: Added support for the heartbeat extension (RFC 6520).
- DTLS: Improve record seq. behaviour in HelloVerifyRequest scenarios.
- TLS: BasicTlsPSKIdentity now reusable (returns cloned array from getPSK).
- BCJSSE: Improved ALPN support, including selectors from Java 9.
- Lightweight RSADigestSigner now support use of NullDigest.
- SM2Engine now supports C1C3C2 mode.
- SHA256withSM2 now added to provider.
- BCJSSE: Added support for ALPN selectors (including in BC extension API for earlier JDKs).
- BCJSSE: Support 'SSL' algorithm for SSLContext (alias for 'TLS').
- The BLAKE2xs XOF has been added to the lightweight API.
- Utility classes added to support journaling of SecureRandom and algorithms to allow persistance and later resumption.
- PGP SexprParser now handles some unprotected key types.
- NONEwithRSA support added to lightweight RSADigestSigner.
- Support for the Ethereum flavor of IES has been added to the lightweight API.

<a id="r1rv61"></a>

### 2.31.1 Version

Release: 1.61\
Date: 2019, February 4th.

### 2.31.2 Defects Fixed

- Use of EC named curves could be lost if keys were constructed via a key factory and algorithm parameters. This has been fixed.
- RFC3211WrapEngine would not properly handle messages longer than 127 bytes. This has been fixed.
- The JCE implementations for RFC3211 would not return null AlgorithmParameters. This has been fixed.
- TLS: Don't check CCS status for hello_request.
- TLS: Tolerate unrecognized hash algorithms.
- TLS: Tolerate unrecognized SNI types.
- An incompatibility issue in ECIES-KEM encryption in cofactor mode has been fixed.
- An issue with XMSS/XMSSMT private key loading which could result in invalid signatures has been fixed.
- StateAwareSignature.isSigningCapable() now returns false when the key has reached it's maximum number of signatures.
- The McEliece KeyPairGenerator was failing to initialize the underlying class if a SecureRandom was explicitly passed.
- The McEliece cipher would sometimes report the wrong value on a call to Cipher.getOutputSize(int). This has been fixed.
- CSHAKEDigest.leftEncode() was using the wrong endianness for multi byte values. This has been fixed.
- Some ciphers, such as CAST6, were missing AlgorithmParameters implementations. This has been fixed.
- An issue with the default "m" parameter for 1024 bit Diffie-Hellman keys which could result in an exception on key pair generation has been fixed.
- The SPHINCS256 implementation is now more tolerant of parameters wrapped with a SecureRandom and will not throw an exception if it receives one.
- A regression in PGPUtil.writeFileToLiteralData() which could cause corrupted literal data has been fixed.
- Several parsing issues related to the processing of CMP PKIPublicationInfo have been fixed.
- The ECGOST curves for id-tc26-gost-3410-12-256-paramSetA and id-tc26-gost-3410-12-512-paramSetC had incorrect co-factors. These have been fixed.

### 2.31.3 Additional Features and Functionality

- The qTESLA signature algorithm has been added to PQC light-weight API and the PQC provider.
- The password hashing function, Argon2 has been added to the lightweight API.
- BCJSSE: Added support for endpoint ID validation (HTTPS, LDAP, LDAPS).
- BCJSSE: Added support for 'useCipherSuitesOrder' parameter.
- BCJSSE: Added support for ALPN.
- BCJSSE: Various changes for improved compatibility with SunJSSE.
- BCJSSE: Provide default extended key/trust managers.
- TLS: Added support for TLS 1.2 features from RFC 8446.
- TLS: Removed support for EC point compression.
- TLS: Removed support for record compression.
- TLS: Updated to RFC 7627 from draft-ietf-tls-session-hash-04.
- TLS: Improved certificate sig. alg. checks.
- TLS: Finalised support for RFC 8442 cipher suites.
- Support has been added to the main Provider for the Ed25519 and Ed448 signature algorithms.
- Support has been added to the main Provider for the X25519 and X448 key agreement algorithms.
- Utility classes have been added for handling OpenSSH keys.
- Support for processing messages built using GPG and Curve25519 has been added to the OpenPGP API.
- The provider now recognises the standard SM3 OID.
- A new API for directly parsing and creating S/MIME documents has been added to the PKIX API.
- SM2 in public key cipher mode has been added to the provider API.
- The BCFKSLoadStoreParameter has been extended to allow the use of certificates and digital signatures for verifying the integrity of BCFKS key stores.

### 2.31.4 Removed Features and Functionality

- Deprecated methods for EC point construction independent of curves have been removed.

<a id="r1rv60"></a>

### 2.32.1 Version

Release: 1.60\
Date: 2018, June 30

### 2.32.2 Defects Fixed

- Base64/UrlBase64 would throw an exception on a zero length string. This has been fixed.
- Base64/UrlBase64 would throw an exception if there was whitespace in the last 4 characters. This has been fixed.
- The SM2 Signature JCE class now properly resets of Signature.sign() is called.
- XMSS applies further validation to deserialisation of the BDS tree so that failure occurs as soon as tampering is detected (see CVE below).
- An off by one error in the JsseDefaultHostnameAuthorizer isValidNameMatch method has been fixed.
- BCJSSE: Return empty byte array instead of null, for the null session ID.
- If a checksum calculator was passed to a PGPSecretKey constructor, but the encryptor was set to null, the wrong checksum would be calculated for the S2K usage. This has been fixed.
- The CRMF EncryptedValue, when containing a private key, held an encoding of an EncryptedPrivateKeyInfo, rather than just the encrypted bytes. This has been fixed.
- EC point precomputations could fail due to race conditions in concurrent settings. Point precomputation was reworked to fix this.
- PGP key rings containing EdDSA signatures would cause an exception on parsing. This has been fixed.
- BCJSSE: a mixed case error for brainpool curves in the supported groups set has been fixed.
- getVersion() on the CRMF CertTemplate class could cause a null pointer exception if the optional version field was left out. This has been fixed.
- Use of a short buffer with RSA via the JCE could result in an escaping ArrayIndexOutOfBoundsException. This has been fixed so that a ShortBufferException is now thrown.
- SM2Engine.decrypt() ignored the offset parameter and assumed zero. This has been fixed.
- A PEM encoded TRUSTED CERTIFICATE missing a trust block would result in a NullPointerException. This has been fixed.
- If the Sun provider was removed entirely the BC SecureRandom was unable to seed and caused an InstantiationException. A back up seeding strategy has been added to prevent this.
- In some situations the use of sm2p256v1 would result in "unknown curve name". This has been fixed.
- CMP PollReqContent now supports multiple certificate request IDs.

### 2.32.3 Additional Features and Functionality

- TLS: Extended CBC padding is now optional (and disabled by default).
- TLS: Now supports channel binding 'tls-server-end-point'.
- TLS: InterruptedIOException (e.g. socket timeout) during app-data reads no longer fails connection; handshake is optionally resumable after IIOE using 'TlsProtocol.setResumableHandshake()'.
- TLS: Added utility methods and constants for ALPN (RFC 7301).
- BCJSSE: Now supports system property 'jdk.tls.client.protocols'
- BCJSSE: Now supports SSLParameters.setSNIMatchers.
- BCJSSE: SNI can now be used in earlier JDKs via BC extensions.
- BCJSSE: Session context now holds sessions via soft references.
- An implementation of CryptoServicesRegistrar has been added to allow configuring of DSA/DH parameters and global setting of the SecureRandom used in the APIs.
- Support has been added for the Unified Model of key agreement for both regular Diffie-Hellman and ECCDH.
- Standard key-wrapping ciphers can now be used for wrapping other data where the cipher supports it.
- BCFKS can now support the use of generalised wrapping algorithms.
- A parser has now been added for the GNU keybox file format.
- The GPG SExpr parser now covers a wider range of key types and validates associated checksums as well.
- PGP EC operations now support more than just NIST curves.
- Restrictions on the output sizes of the Blake2b/s digests in the lightweight API have been removed.
- The Whirlpool digest OID has been added to its corresponding mappings for the JCA.
- Support has been added for SHA-3 based signatures to the CMS API.
- Support has been added to the CMS API for the generation of ECGOST key transport messages.
- The ECElGamalEncryptor now supports the use of ECGOST curves.
- The number of signature subpackets in OpenPGP signatures that are converted into explicit types automatically has been increased.
- RFC 8032: Added low-level implementations of Ed25519 and Ed448.
- The provider jars now include a services entry for the 2 providers they hold.
- Support has been added for the German BSI KAEG Elliptic Curve key agreement algorithm with X9.63 as the KDF to the JCE.
- Support has been added for the German BSI KAEG Elliptic Curve session key KDF to the lightweight API.

### 2.32.4 Security Related Changes and CVE's Addressed by this Release

- CVE-2018-1000180: issue around primality tests for RSA key pair generation if done using only the low-level API.
- CVE-2018-1000613: lack of class checking in deserialization of XMSS/XMSS^MT private keys with BDS state information.

<a id="r1rv59"></a>

### 2.33.1 Version

Release: 1.59\
Date: 2017, December 28

### 2.33.2 Defects Fixed

- Issues with using PQC based keys with the provided BC KeyStores have now been fixed.
- ECGOST-2012 public keys were being encoded with the wrong OID for the digest parameter in the algorithm parameter set. This has been fixed.
- SM3 has now been added as an acceptable algorithm for TSP timestamps.
- SM2 signatures were using the wrong default identity value. This has now been fixed.
- An edge condition in Blake2b for hashes on data with a length in the range of 2\*\*64 - 127 to 2\*\*64 has been identifed and fixed.
- The ISO Trailer for SHA512/256 used in X9.31 and ISO9796-2 signatures was incorrect. This has been fixed.
- The BCJSSE SSLEngine implementation now correctly wraps/unwraps application data only in whole records.
- The curve parameters for tc26_gost_3410_12_256_paramSetA were incorrect. These have been fixed.
- Further work has been done to try and prevent escaping exceptions on opening random files as BCFKS files or PKCS#12 files.
- An off-by-one error for the max N check for SCRYPT has been fixed. SCRYPT should now be compliant with RFC 7914.
- ASN1GeneralizedTime will now accept a broader range of input strings.

### 2.33.3 Additional Features and Functionality

- GOST3410-94 private keys encoded using ASN.1 INTEGER are now accepted in private key info objects.
- SCRYPT is now supported as a SecretKeyFactory in the provider and in the PKCS8 APIs
- The BCJSSE provider now supports session resumption in clients.
- The BCJSSE provider now supports Server Name Indication.
- The BCJSSE provider now supports the jdk.tls.namedGroups system property.
- The BCJSSE provider now supports the org.bouncycastle.jsse.ec.disableChar2 system property, which optionally disables the use of characteristic-2 elliptic curves.
- EC key generation and signing now use cache-timing resistant table lookups.
- Performance of the DSTU algorithms has been greatly improved.
- Support has been added for generating certificates and signatures in the PKIX API using SHA-3 based digests.
- Further work has been done on improving SHA-3 performance.
- The organizationIdentifier (2.5.4.97) attribute has been added to BCStyle.
- GOST3412-2015 has been added to the JCE provider and the lightweight API.
- The Blake2s message digest has been added to the provider and the lightweight API.
- Unified Cofactor Diffie-Hellman (ECCDHU) is now supported for EC in the JCE and the lightweight API.
- A DEROtherInfo generator for key agreement using NewHope as the source of the shared private info has been added that can be used in conjunction with regular key agreement algorithms.
- RFC 7748: Added low-level implementations of X25519 and X448.

### 2.33.4 Security Related Changes and CVE's Addressed by this Release

- CVE-2017-13098 ("ROBOT"), a Bleichenbacher oracle in TLS when RSA key exchange is negotiated. This potentially affected BCJSSE servers and any other TLS servers configured to use JCE for the underlying crypto - note the two TLS implementations using the BC lightweight APIs are not affected by this.

<a id="r1rv58"></a>

### 2.34.1 Version

Release: 1.58\
Date: 2017, August 18

### 2.34.2 Defects Fixed

- NewHope and SPHINCS keys are now correctly created off certificates by the BC provider.
- Use of the seeded constructor with SecureRandom() and the BC provider in first position could cause a stack overflow error. This has been fixed.
- The boolean flag on ECDSAPublicKey in CVCertficate was hard coded. This has been fixed.
- An edge condition in IV processing for GOFB mode has been found and fixed.
- ANSSI named EC curves were not being recognised in PKCS#10 and certificate parsing. This has been fixed.
- BaseStreamCipher.engineSetMode() could sometimes throw an IllegalArgumentException rather than a NoSuchAlgorithmException. This has been fixed.
- Some class resolving used by the provider would fail if the BC jar was loaded on the boot class path. This has been fixed.
- An off-by-one range check in SM2Signer has been fixed.
- Retrieving an SM2 key from a certificate could result in a NullPointerException due to a problem with the curve lookup. This has been fixed.
- A race condition that could occur inside the HybridSecureRandom on reseed and result in an exception has been fixed.
- DTLS now supports records containing multiple handshake messages.

### 2.34.3 Additional Features and Functionality

- An implementation of GOST3410-2012 has been added to light weight API and the JCA provider.
- Support for ECDH GOST3410-2012 and GOST3410-2001 have been added. The CMS API can also handle reading ECDH GOST3410 key transport messages.
- Additional mappings have been added for a range of CVC-ECDSA algorithms.
- XMMS and XMSSMT are now available via the BCPQC provider. Support has been added for using these keys in certificates as well.
- Support has been added for DSTU-7564 message digest and the DSTU-7624 ciphers, together with their associated modes.
- A new system property org.bouncycastle.asn1.allow_unsafe_integer has been added to allow parsing of malformed ASN.1 integers in a similar fashion to what BC 1.56 did. The default behavior remains as reject malformed integers.
- SignedMailValidator would only pick up the first email address in a DN, even when there was more than one. This has been fixed.
- PEMParser will now support a broader range of PBKDFs in encrypted private key files.
- Work has been done on speeding up the SHA-3 family. The functions are now 3 to 4 times faster.
- Some EC aliases in the provider had no corresponding implementations. These have been cleaned up.
- TimeStampResponses now support definite-length encoding to allow the preservation of order in certificates sets for legacy responses.
- The TSP API now supports SM2withSM3.
- The BCJSSE provider now has a FIPS mode.
- The BCJSSE provider now supports layered sockets.
- The new TLS API now has protocol/API support for the status_request extension (OCSP stapling).
- The new TLS API now supports RFC 7633 - X.509v3 TLS Feature Extension (e.g. "must staple"), enabled in default clients.
- TLS exceptions have been made more directly informative.

### 2.34.4 Removed Features and Functionality

- Per RFC 7465, removed support for RC4 in the new TLS API.
- Per RFC 7568, removed support for SSLv3 in the new TLS API.

<a id="r1rv57"></a>

### 2.35.1 Version

Release: 1.57\
Date: 2017, May 11

### 2.35.2 Defects Fixed

- A class cast exception for master certification removal in PGPPublicKey.removeCertification() by certification has been fixed.
- GOST GOFB 28147-89 mode had an edge condition concerning the incorrect calculation of N4 (see section 6.1 of RFC 5830) affecting about 1% of IVs. This has been fixed.
- The X.509 PolicyConstraints class was using implicit rather than explicit tagging for the SkipCerts field. This has been fixed.
- Key expiration in the OpenPGP is now calculated for ambiguous self signatures using the most recently created self-signature, in line with GPG and the recommendation in RFC 4880.
- Multiple validity periods in PGP keys were resolved in an adhoc fashion, in line with GPG's approach the PGP has been changed to return the most recent validity period signed.
- An occasional class cast exception that could occur with nested multi-parts in the S/MIME API has been fixed.
- A couple of bogus aliases associated AlgorithmParameters that did not resolve in the provider have been removed.
- The CMS API will now correctly verify PSS signatures with odd length salts.
- Choosing an invalid mode on a stream cipher in the JCE could result in an IllegalArgumentException. This has now been corrected to throw a NoSuchAlgorithmException.
- Optional parameters for ECDSA public keys in CVCertificates were hard coded to non-optional. This has been fixed.
- Passing a PKCS12 key to a Mac in the BC JCE always resulted in SHA-1 being used to process the password regardless of the underlying MAC algorithm. This has been fixed. An unrecognised HMAC will also now result in an exception.
- The Base64 encoder now explicitly validates 2 character padding as being "==".
- EC FixedPointCombMultiplier avoids 'infinity' point in lookup tables, reducing timing side-channels.
- Reuse of a Blake2b digest with a call to reset() rather than doFinal() could result in incorrect padding being introduced and the wrong digest result produced. This has been fixed.

### 2.35.3 Additional Features and Functionality

- ARIA (RFC 5794) is now supported by the provider and the lightweight API.
- ARIA Key Wrapping (RFC 5649 style) is now supported by the provider and the lightweight API.
- SM2 signatures, key exchange, and public key encryption has been added to the lightweight API.
- XMSS has been added to the lightweight PQ API. Note: this should be treated as beta code.
- API support for client side EST (RFC 7030), as well as some CMC (RFC 5273) has been added to the PKIX API. A full set of ASN.1 classes for both protocols has been added as well.
- A test client for EST which will interop with the 7030 test server at http://testrfc7030.com/ has been added to the general test module in the current source tree.
- The BCJSSE provider now supports SSLContext.getDefault(), with very similar behaviour to the SunJSSE provider, including checks of the relevant javax.net.ssl.\* system properties and auto-loading of jssecacerts or cacerts as the default trust store.

### 2.35.4 Security Related Changes

- The default parameter sizes for DH and DSA are now 2048. If you have been relying on key pair generation without passing in parameters generated keys will now be larger.
- Further work has been done on preventing accidental re-use of a GCM cipher without first changing its key or iv.

<a id="r1rv56"></a>

### 2.36.1 Version

Release: 1.56\
Date: 2016, December 23

### 2.36.2 Defects Fixed

- See section [2.35.4](#CVE156) for Security Defects.
- Using unknown status with the ASN.1 CertStatus primitive could result in an IllegalArgumentException on construction. This has been fixed.
- A potentional NullPointerException in a precomputation in WNafUtil has been removed.
- PGPUtil.getDecoderStream() would throw something other than an IOException for empty and very small data. This has been fixed.

### 2.36.3 Additional Features and Functionality

- Support for the explicit setting of AlgorithmParameters has been added to the JceCMSContentEncryptorBuilder and the JceCMSMacCaculatorBuilder classes to allow configuration of the session cipher/MAC used.
- EC, ECGOST3410, and DSTU4145 Public keys are now validated on construction in the JCA/JCE and the light weight API.
- DSA Public keys are now validated on construction in the JCA/JCE and the light weight API.
- Diffie-Hellman public keys are now validated where parameters allow it.
- Some validations are now applied to RSA moduli and public exponents.
- The ASN.1 Object Identifier cache now uses a Concurrent HashMap for additional speed.
- AES-CCM MAC support has been added to the provider.
- Support for ChaCha7539 (ChaCha20 as defined in RFC 7539) and Poly1305 have been added to the provider.
- Support has been added for defining your own curves and making them available to the key generators and factories.
- Methods have been added for specifying that a PGPPublicKey/PGPPublicKeyRing is being encoded for export and trust packets are not required.
- Plain-ECDSA and SHA-3 support has been added to DefaultDigestAlgorithmIdentifierFinder.
- SHA-3 support has been added to BcDefaultDigestProvider.
- A higher level TLS API and JSSE provider have been added to the project.

<a id="CVE156"></a>

### 2.36.4 Security Related Changes and CVE's Addressed by this Release

- It is now possible to configure the provider to only import keys for specific named curves.
- Work has been done to improve the "constant time" behaviour of the RSA padding mechanisms.
- The GCM ciphers in the JCE and lightweight API will now fail if an attempt is made to use them for encryption after a doFinal or without changing the IV.
- The constructor for IESParameterSpec that allows the use of cipher without a nonce has been deleted. See also details for CVE-2016-1000344, CVE-2016-1000352.
- Strict encoding enforcement has been introduced for ASN1Integer.
- CVE-2016-1000338: DSA does not fully validate ASN.1 encoding of signature on verification. It is possible to inject extra elements in the sequence making up the signature and still have it validate, which in some cases may allow the introduction of "invisible" data into a signed structure.
- CVE-2016-1000339: AESFastEngine has a side channel leak if table accesses can be observed. The use of lookup large static lookup tables in AESFastEngine means that where data accesses by the CPU can be observed, it is possible to gain information about the key used to initialize the cipher. We now recommend not using AESFastEngine where this might be a concern. The BC provider is now using AESEngine by default.
- CVE-2016-1000340: Static ECDH vulnerable to carry propagation bug. Carry propagation bugs in the implementation of squaring for several raw math classes have been fixed (org.bouncycastle.math.raw.Nat???). These classes are used by our custom elliptic curve implementations (org.bouncycastle.math.ec.custom.\*\*), so there was the possibility of rare (in general usage) spurious calculations for elliptic curve scalar multiplications. Such errors would have been detected with high probability by the output validation for our scalar multipliers.
- CVE-2016-1000341: DSA signature generation vulnerable to timing attack. Where timings can be closely observed for the generation of signatures, the lack of blinding in 1.55 or earlier, may allow an attacker to gain information about the signatures k value and ultimately the private value as well.
- CVE-2016-1000342: ECDSA does not fully validate ASN.1 encoding of signature on verification. It is possible to inject extra elements in the sequence making up the signature and still have it validate, which in some cases may allow the introduction of "invisible" data into a signed structure.
- CVE-2016-1000343: DSA key pair generator generates a weak private key if used with default values. If the JCA key pair generator is not explicitly initialised with DSA parameters, 1.55 and earlier generates a private value assuming a 1024 bit key size. In earlier releases this can be dealt with by explicitly passing parameters to the key pair generator.
- CVE-2016-1000344: DHIES allows the use of unsafe ECB mode. This algorithm is now removed from the provider.
- CVE-2016-1000345: DHIES/ECIES CBC mode vulnerable to padding oracle attack. For BC 1.55 and older, in an environment where timings can be easily observed, it is possible with enough observations to identify when the decryption is failing due to padding.
- CVE-2016-1000346: Other party DH public key not fully validated. This can cause issues as invalid keys can be used to reveal details about the other party's private key where static Diffie-Hellman is in use. As of this release the key parameters are checked on agreement calculation.
- CVE-2016-1000352: ECIES allows the use of unsafe ECB mode. This algorithm is now removed from the provider.

### 2.36.5 Security Advisory

- We consider the carry propagation bugs fixed in this release to have been exploitable in previous releases (1.51-1.55), for static ECDH, to reveal the long-term key, per ["Practical realisation and elimination of an ECC-related software bug attack", Brumley et.al.](https://eprint.iacr.org/2011/633). The most common case of this would be the non-ephemeral ECDH ciphersuites in TLS. These are not enabled by default in our TLS implementations, but they can be enabled explicitly by users. We recommend that users DO NOT enable static ECDH ciphersuites for TLS.

<a id="r1rv55"></a>

### 2.37.1 Version

Release: 1.55\
Date: 2016, August 18

### 2.37.2 Defects Fixed

- Issues with cloning of blake digests with salts and personalisation strings have been fixed.
- The JceAsymmetricValueDecryptor in the CRMF package now attempts to recognise a wider range of parameters for the key wrapping algorithm, rather than relying on a default.
- GCM now fails if an attempt is made to go past 2^32-1 blocks.
- (r, k) ordering for Poly1305 has been modified to be brought into line with RFC 7539.
- An occasional error in Poly1305 due to sign-extension has been fixed.
- TimeStampRequest was always failing to validate if extensions were present. This has been fixed.
- ECIES/IES algorithm parameters encoding failed on default parameters. This has been fixed.
- PGPObjectFactory.iterator() could fail when called on data with multiple stream packets. This has been fixed.
- The McEliece implementation in the BCPQC provider has been revised and now has working key factories associated with it.
- The X.509 UserNotice class can now cope with empty sequences.
- Creation of multiple providers concurrently could cause issues with a non-synchronized Map in the provider. Code is now synchronized.
- If the lightweight OAEP encoder is fed oversized input it will now throw something more informative than an ArrayOutOfBoundsException or simply truncate.
- Attempting to use the PasswordRecipientInfoGenerator without explicitly setting the salt would cause a NullPointerException. This has been fixed.
- The BasicConstraintsValidation in the CertPath API would throw a NullPointerException on an unconstrained path length. This has been fixed.
- A shift error for \> 24 bit numbers in TlsUtils has been fixed.
- OAEP encryption for a zero length message would create invalid cipher text. This has been fixed.
- Trying to use of non-default parameters for OAEP in CRMF would resort to the default parameter set. This has been fixed.
- If the BC provider was not registered, creating a CertificateFactory would cause a new provider object to be created. This has been fixed.

### 2.37.3 Additional Features and Functionality

- The DANE API has been updated to reflect the latest standard changes.
- The signature algorithm SPHINCS-256 has been added to the post-quantum provider (BCPQC). Support is in place for SHA-512 and SHA3-512 (using trees based around SHA512_256 and SHA3_256 respectively).
- The key exchange algorithm NewHope has been added to the post-quantum provider (BCPQC). Support is in place for the regular configuration using SHA3-256 as the flattening algorithm for the agreed value.
- The CMS password recipient generator now allows the PRF to be changed to something other than SHA-1
- Direct support for the SignatureTarget packet has been added to the OpenPGP API.
- TLS: support for ClientHello Padding Extension (RFC 7685).
- TLS: support for ECDH_anon key exchange.
- Support has been added for HMAC SHA-3. Aliases have been added for NIST OIDs for SHA-3 HMAC as well.
- Support has been added for SHA-3 in DSA, ECDSA, DDSA, and ECDDSA. Aliases have been added for NIST OIDs for DSA and ECDSA as well.
- Support has been added for SHA-3 with RSA PKCS 1.5, PSS, and OAEP.
- Support has been added for GOST R 34.11-2012 to the provider and the lightweight API.
- PGP armored output can now be generated without a version string.
- The TimeStampTokenGenerator will now generate timestamps down to a millisecond resolution.
- Additional search methods have been added to PGP public and secret key rings.

<a id="r1rv54"></a>

### 2.38.1 Version

Release: 1.54\
Date: 2015, December 29

### 2.38.2 Defects Fixed

- Blake2b-160, Blake2b-256, Blake2b-384, and Blake2b-512 are now actually in the provider and an issue with cloning Blake2b digests has been fixed.
- PKCS#5 Scheme 2 using DESede CBC is now supported by the PKCS#12 implementation.
- The IES engine would sometimes throw a "too short" exception on small messages which were the right length. This has been fixed.
- Cipher.getOutputSize() for IES ciphers would throw a ClassCastException. This has been fixed.
- It turns out, after advice one way and another that the NESSIE test vectors for Serpent are now what should be followed and that the vectors in the AES submission are regarded as an algorithm called Tnepres. The Serpent version now follows the NESSIE vectors, and the Tnepres cipher has been added to the provider and the lightweight API for compatibility.
- Problems with DTLS record-layer version handling were resolved, making version negotiation work properly.

### 2.38.3 Additional Features and Functionality

- Camellia and SEED key wrapping are now supported for CMS key agreement
- The BC TLS/DTLS code now includes a non-blocking API.
- CTR/SIC mode now support an internal counter. The internal counter can be turned on by passing an IV smaller than the block size of the cipher's algorithm.
- The lightweight CMS API operators now support CAST5 and RC2 CBC encryption.
- The CMS API now supports Diffie-Hellman as specified in RFC 3370.
- Support has been added to the CMS API for PKCS#7 ANY type encapsulated content where the encapsulated content is not an OCTET STRING.
- PSSSigner in the lightweight API now supports fixed salts.

### 2.38.4 Security Advisory

- (D)TLS 1.2: Motivated by [CVE-2015-7575](https://www.google.com/search?q=CVE-2015-7575), we have added validation that the signature algorithm received in DigitallySigned structures is actually one of those offered (in signature_algorithms extension or CertificateRequest). With our default TLS configuration, we do not believe there is an exploitable vulnerability in any earlier releases. Users that are customizing the signature_algorithms extension, or running a server supporting client authentication, are advised to double-check that they are not offering any signature algorithms involving MD5.

### 2.38.5 Notes

If you have been using Serpent, you will need to either change to Tnepres, or take into account the fact that Serpent is now byte-swapped compared to what it was before.

<a id="r1rv53"></a>

### 2.39.1 Version

Release: 1.53\
Date: 2015, October 10

### 2.39.2 Defects Fixed

- The BC JCE cipher implementations could sometimes fail when used in conjunction with the JSSE and NIO. This has been fixed.
- PGPPublicKey.getBitStrength() always returned 0 for EC keys. This has been fixed.
- A PKCS12 key store containing a looping certificate chain could cause an OutOfMemoryException. This has been fixed.
- A change in JDK 1.8 meant that X509Certificate.verify(PublicKey, Provider) would cause a stack overflow. This has been fixed.
- Nested multiparts with irregular post-amble could cause verification issues for the SMIMESigned classes. This has been fixed.
- CMSSignedData now supports verification of signed attributes where the calculated digest uses a different algorithm from the digest used in the signature.
- TRUSTED CERTIFICATE parsing in PEM files was ignoring the attribute block. A new class X509TrustedCertificateBlock is now returned containing both the certificate and the trust information.
- Adding a password to a PGP key which did not previously have one would result in an improperly formatted key. This has been fixed.
- ECIES/IES was only using a 4 byte label length for the MAC tag when it should have been an 8 byte one. This has now been fixed and OldECIES/OldIES has been added for backwards compatibility.
- The JceCRMFEncryptorBuilder was not recognising key size specific object identifiers properly. This has been fixed.
- The OpenPGP ClearSignedFileProcessor would not handle verification of single line files properly. This has been fixed.
- The BC X509Certificate class was no longer in agreement with the standard class for hashCode(). The BC X509Certificate class will now track the changes made in the standard Java distribution.
- PGP signature hashed sub-packets with long length encodings would fail to validate on signature checking. This has been fixed.
- The S/MIME API would occasionally leak InputStreams which could cause issues with custom DataSource implementations. This has been fixed.
- The PKCS#12 KeyStore implementation would sometimes leave orphaned chain certificates in the key store after private key deletion. This has been fixed.
- A bug in the DirectKeySignature OpenPGP example which could lead to extra data appearing in the signature has been fixed.
- Explicit configuration of a BcAsymmetricKeyWrapper with a SecureRandom was not properly propagated internally. This has been fixed.
- A CRL with a null certificate issuer would sometimes result in a NullPointerException during CertPathProcessing. This has been fixed.
- The CertPath processor would occasionally fail to match a DistributionPoint name correctly. This has been fixed.
- In order to avoid confusion about thread safety, BCrypt now uses a new instance for hash calculation every time it is invoked.
- Some decidedly odd argument casting in the PKIXCertPathValidator has been fixed to throw an InvalidAlgorithmParameterException.
- Presenting an empty array of certificates to the PKIXCertPathValidator would cause an IndexOutOfRangeException instead of a CertPathValidatorException. This has been fixed.

### 2.39.3 Additional Features and Functionality

- It is now possible to specify that an unwrapped key must be usable by a software provider in the asymmetric unwrappers for CMS.
- A Blake2b implementation has been added to the provider and lightweight API.
- SHA3 has now been added to the provider and the lightweight API. SHAKE128 and SHAKE256 have also been added to the lightweight API. The original implementation of the draft standard has been renamed to Keccak.
- The CMS API now supports RFC 6211 for both SignedData and AuthenticatedData.
- The ASN.1 parser for ECGOST private keys will now parse keys encoded with a private value represented as an ASN.1 INTEGER.
- EAX mode and CMAC is now supported for ciphers such as SHACAL-2 and Threefish.
- The SM4 block cipher has been added to the provider and the lightweight API.
- X9.31, ISO9796/2, and PSS signature support has been added for SHA512/224, SHA512/256.
- SubjectPublicKeyInfoFactory now supports DSA parameters.
- A range of new algorithms are now support for EC key agreement.
- EC ContentSigners and EC ContentVerifiers have been added to the lightweight operator package in the PKIX APIs.
- The PKCS#12 key store will now garbage collect orphaned certificates on saving.
- Caching for ASN.1 ObjectIdentifiers has been rewritten to make use of an intern method. The "usual suspects" are now interned automatically, and the cache is used by the parser. Other OIDs can be added to the cache by calling ASN1ObjectIdentifier.intern().

### 2.39.4 Notes

It turns out there was a similar, but different, issue in Crypto++ to the BC issue with ECIES. Crypto++ 6.0 now offers a corrected version of ECIES which is compatible with that which is now in BC.

<a id="r1rv52"></a>

### 2.40.1 Version

Release: 1.52\
Date: 2015, March 2

### 2.40.2 Defects Fixed

- GenericSigner in the lightweight API would fail if the digest started with a zero byte, occasionally causing a TLS negotiation to fail. This has been fixed.
- Some BC internal classes expected the BC provider to be accessible within the provider. This has been fixed.
- Email based policy constraints in CertPath validation did not include '@'domain.name as a possible match. This has been fixed.
- The Shacal2Engine would throw an ArrayIndexOutOfBoundsException if presented with input longer than a block size. This has been fixed.
- Using PKCS5/PKCS7 with pad values greater than 127 would result in an exception on decryption. This has been fixed.
- EC private key values could encode to an OCTET STRING which was shorter than that described in RFC 5915/SEC 1. This has been fixed.
- Providing multiple trust anchors to the CertPath validator could cause a StackOverflowError on an invalid CertPath. This has been fixed.
- TLS: bad-padding handling when encrypt-then-MAC enabled is now fixed.
- ECDH KeyAgreement.init() was not properly honoring the JCE API in respect to non-null parameters. This has been fixed.
- PKCS symmetric padding now takes into account pad lengths of more than 127 bytes.
- Corrupted input to RFC5649WrapEngine could cause an out of memory error. This has been fixed.
- OSGI import issues for bcmail have been fixed.
- A badly formed issuer in a X.509 certificate could cause a null pointer exception in X509CertificateHolder.toString(). This has been fixed.
- CMSSignedData.verifySignatures() could fail on a correct counter signature due to a mismatch of the SID. This has been fixed.

### 2.40.3 Additional Features and Functionality

- The CMP support class CMPCertificate restricted the types of certificates that could be added. A more flexible method has been introduced to allow for other certificate types.
- Support classes have be added for DNS-based Authentication of Named Entities (DANE) to the PKIX distribution.
- Work has been done to reduce computation requirements for long skips associated with implementations of the SkippingCipher interface.
- AES GCM mode is now supported by CMS EnvelopedData.
- Iteration count is now settable in BcPKCS12MacCalculatorBuilder.
- Support for BCrypt and it's OpenBSD variant has been added to the lightweight API.
- It's now possible to specify the direction of the underlying cipher used for key wrapping with NIST/RFC3394 wrappers.
- TLS: server-side support for DHE key exchange.
- TLS: server-side support for PSK and SRP ciphersuites.
- TLS: (EC)DSA now supports signatures with non-SHA1 digests.
- TLS: support for ECDHE_ECDSA/AES/CCM ciphersuites from RFC 7251.
- Cipher.getIV() now returns nonces for AEAD modes.
- OIDs for dhPublicNumber and dhKeyAgreement are now supported by the provider.
- OIDs for several signature types using the RIPEMD family of digests have been added to the provider.
- JcaJceUtils.getDigestAlgName() has been added to assist in converting OIDs representing message digests into JCA algorithm names.
- BasicOCSPResp.getSignatureAlgorithmID() has been added to allow algorithm indentifier details to be returned from a basic OCSP response.
- Additional OIDs have been added for OCSP.
- X509CRLObject.getSignAlgName() now attempts to return an actual name, rather than an OID for, for the signature algorithm.
- SignedMailValidator now pays attention to the date in the PKIXParameters object if it is set.
- A missing signing time in a signature no longer causes SignedMailValidator to fail a signature, but provide a warning instead.
- An AlgorithmNameFinder implementation has been added to the PKIX API to provide "human friendly" translations of algorithm OIDs.
- Support has been added for X9.31-1998 DRBG and X9.31-1998 RSA signatures to the lightweight API and the provider.
- CertPath validator will now make use of the issuer key identifier and the issuer name if a key identifier is available for the issuer.
- Support for some JDK1.5+ language features has finally made its way into the repository.
- A load store parameter, PKCS12StoreParameter, has been added to support DER only encoding of PKCS12 key stores.

### 2.40.4 Security Advisory

- The CTR DRBGs would not populate some bytes in the requested block of random bytes if the size of the block requested was not an exact multiple of the block size of the underlying cipher being used in the DRBG. If you are using the CTR DRBGs with "odd" keysizes, we strongly advise upgrading to this release, or contacting us for a work around.

<a id="r1rv51"></a>

### 2.41.1 Version

Release: 1.51\
Date: 2014, July 28

### 2.41.2 Defects Fixed

- The AEAD GCM AlgorithmParameters object was unable to return a GCMParameterSpec object. This has been fixed.
- Cipher.getIV() was returning null for AEAD mode ciphers. This has been fixed.
- CipherInputStream would fail for some AEAD mode ciphers if the message was over 4k in length. This has been fixed.
- The JCE provider will now produce simple RSAPrivateKey objects where CRT coefficients are not provided.
- PGP key signature certifications did not support DIRECT KEY signatures. This has been fixed.
- User Attribute subpackets in PGP with long length encodings could result in certification verification failing. This has been fixed.
- Calls to CommandMap.setDefaultCommandMap() in the SMIME API are now wrapped in doPrivileged() blocks to allow them to work with a security manager.
- The encoding of the certificate_authorities field of a TLS CertificateRequest has been fixed.
- EC point formats are now strictly enforced in the TLS API.
- The provider implementation was failing to throw an exception if algorithm parameters were passed in when none were required for EC key agreement. This has been fixed.
- PKCS#12 files containing keys/certificates with empty attribute sets attached to them no longer cause an ArrayIndexOutOfBoundsException to be thrown.
- Issues with certificate verification and server side DTLS/TLS 1.2 have now been fixed.

### 2.41.3 Additional Features and Functionality

- The range of key algorithm names that will be interpreted by KeyAgreement.generateSecret() has been expanded for ECDH derived algorithms in the provider. A KeyAgreement of ECDHwithSHA1KDF can now be explicitly created.
- ECIES now supports the use of IVs with the underlying block cipher and CBC mode in both the lightweight and the JCE APIs.
- Support has been add for RFC5649 key wrapping using AES.
- The PGP API now allows access and handling of User IDs as raw byte arrays, to deal with keyrings not using UTF-8.
- The PGP API now provides automatic conversion of embedded signatures in signature sub-packet vectors.
- The PGP API now fully supports ECDH as outlined in RFC 6637.
- GCM and GMAC now support tag lengths down to 32 bits.
- Custom implementations for many of the SEC Fp curves have been added, resulting in drastically improved performance. The current list includes all secp\*\*\*k1 and secp\*\*\*r1 curves from 192 to 521 bits. They can be accessed via the org.bouncycastle.crypto.ec.CustomNamedCurves class and are generally selected by other internal APIs in place of the generic implementations.
- Automatic EC point validation added, both for decoded inputs and multiplier outputs.
- A SkippingCipher interface has been added for ciphers that can be moved into a specific state for a given byte address. The lightweight class StreamBlockCipher has been generalised to support any BlockCipher object that can support a streaming mode.
- ASN.1 date/time objects now support the passing in of a Locale to allow for constructing the object using a Date interpreted from a different locale to the default for the JVM.
- The range of Diffie-Hellman OIDs recognised by the provider has been extended.
- Some utility methods for interpreting OIDs have been exposed in the JcaJceUtils class.
- A method has been added to CMSSignedData for replacing the OCSP responses associated with a signed message.
- Use of RC2/RC4 in the CMS is now provider independent.
- TlsInputStream now provides a means of supporting InputStream.available().
- Dependencies on the JCA have been removed from PGPObjectFactory.
- Further work has been done on improving key quality with EC and DSA algorithms.
- KDFCounterBytesGenerator now supports suffix and prefix fixed input data, as outlined in NIST SP 800-108.
- Support has been added to allow retrieval and resetting the internal state of the SHA/SHA-2 digests in the lightweight API using an encoded format.
- BSI plain ECDSA is now supported by the provider.
- The provider now advertises RSA PSS signature implementations directly using the standard naming.
- Full support is now provided for client-side auth in the D/TLS server code.
- Compatibility issues with some OSGI containers have been addressed.

### 2.41.4 Notes

- Support for NTRUSigner has been deprecated as the algorithm has been withdrawn.
- Some changes have affected the return values of some methods. If you are migrating from an earlier release, it is recommended to recompile before using this release.
- There has been further clean out of deprecated methods in this release. If your code has previously been flagged as using a deprecated method you may need to change it. The OpenPGP API is the most heavily affected.

<a id="r1rv50"></a>

### 2.42.1 Version

Release: 1.50\
Date: 2013, December 3

### 2.42.2 Defects Fixed

- The DualECSP800DRBG sometimes truncated the last block in the generated stream incorrectly. This has been fixed.
- Keys produced from RSA certificates with specialised parameters would lose the parameter settings. This has been fixed.
- OAEP parameters were being ignored on CMS key trans recipient processing. This has been fixed.
- OpenPGP NotationData was restricting the name and value lengths to 255 characters and truncating silently. This has been fixed.
- CTS mode is now in alignment with the errata for RFC 2040, as detailed in RFC 3962.
- Occasionally the provider implementation of DH KeyAgreement would drop a leading zero byte off the start of the shared secret (see RFC 2631 2.1.2). This has been fixed.
- RFC3394WrapEngine was ignoring the offset parameter inOff and using zero instead. This has been fixed.
- GOST keys would not encode using the CryptoPro parameter set, even if it was available. This has been fixed.
- The TimeStampRequest stream constructor was not setting the extensions field correctly. This has been fixed.
- Default RC2 parameters for 40 bit RC2 keys in CMSEnvelopedData were encoding incorrectly. This has been fixed.
- In case of a long hash the DSTU4145 implementation would sometimes remove one bit too much during truncation. This has been fixed.

### 2.42.3 Additional Features and Functionality

- Additional work has been done on CMS recipient generation to simplify the generation of OAEP encrypted messages and allow for non-default parameters.
- OCB implementation updated to account for changes in draft-irtf-cfrg-ocb-03.
- RFC 6637 ECDSA and ECDH support has been added to the OpenPGP API.
- Implementations of Threefish and Skein have been added to the provider and the lightweight API.
- Implementations of the SM3 digest have been added to the provider and the lightweight API.
- The 3 MAC based KDF generators in NIST SP 800-108 have been added to the lightweight API.
- Support has been added for the GOST PKCS#5 PBKDF2 PBE function and handling of GOST PKCS#12 files.
- Support has been added for the CryptoPro GOST CFB mode key meshing.
- Implementations of XSalsa20 and ChaCha have been added. Support for reduced round Salas20 has been added.
- Support has been added for RFC 6979 Determinstic DSA/ECDSA to the provider and the lightweight API.
- Support for RC2 and RC4 in the CMS API has been generalised to work for other JCE providers.
- Support for the Poly1305 MAC has been added to the lightweight API and the JCE Provider.
- OpenSSL JcaPEMKeyConverter now supports OIDs for RSA and DSA as well as ECDSA.
- A simplified certificate path API has been added to the PKIX package. It is not fully NIST compliant yet, however it does provide a range of basic validations without having to use the JCA.
- Package version information is now included in the jar MANIFEST.MF.
- The JDK 1.5+ provider will now recognise and use GCMParameterSpec if it is run in a 1.7 JVM.
- Client side support and some server side support has been added for TLS/DTLS 1.2.

### 2.42.4 Notes

- org.bouncycastle.crypto.DerivationFunction is now a base interface, the getDigest() method appears on DigestDerivationFunction.
- Recent developments at NIST indicate the SHA-3 may be changed before final standardisation. Please bare this in mind if you are using it.
- Other recent developments have raised concerns about the DualECDRBG. We have left the class in place for now, but it is now possible to provide your own parameter values, rather than using the NIST defined ones, if you choose to do so.
- Most deprecated methods have been removed from the PKIX API.
- As the IDEA patent has finally expired, IDEA is now supported by the standard provider.
- ECDH support for OpenPGP should still be regarded as experimental. It is still possible there will be compliance issues with other implementations.

<a id="r1rv49"></a>

### 2.43.1 Version

Release: 1.49\
Date: 2013, May 31

### 2.43.2 Defects Fixed

- Occasional ArrayOutOfBounds exception in DSTU-4145 signature generation has been fixed.
- The handling of escaped characters in X500 names is much improved.
- The BC CertificateFactory no longer returns null for CertificateFactory.getCertPathEncodings().
- PKCS10CertificationRequestBuilder now encodes no attributes as empty by default. Encoding as absent is still available via a boolean flag.
- DERT61String has been reverted back to its previous implementation. A new class DERT61UTF8String has been introduced which defaults to UTF-8 encoding.
- OAEPEncoding could throw an array output bounds exception for small keys with large mask function digests. This has been fixed.
- PEMParser would throw a NullPointerException if it ran into explicit EC curve parameters, it would also throw an Exception if the named curve was not already defined. The parser now returns X9ECParmameters for explicit parameters and returns an ASN1ObjectIdentifier for a named curve.
- The V2TBSCertListGenerator was adding the wrong date type for CRL invalidity date extensions. This has been fixed.

### 2.43.3 Additional Features and Functionality

- A SecretKeyFactory has been added that enables use of PBKDF2WithHmacSHA.
- Support has been added to PKCS12 KeyStores and PfxPdu to handle PKCS#5 encrypted private keys.
- Support has been added for SHA-512/224, SHA-512/256, as well as a general SHA-512/t in the lightweight API.
- The JcaPGPPrivateKey class has been added to provide better support in the PGP API for HSM private keys.
- A new KeyStore type, BKS-V1, has been added for people needing to create key stores compatible with earlier versions of Bouncy Castle. Please note this keystore type offers a reduced integrity check of 16 bits and the rgular BKS should be used where possible.
- Some extra generation methods have been added to TimeStampResponseGenerator to allow more control in the generation of TimeStampResponses.
- It is now possible to override the SignerInfo attributes during TimeStampTokenGeneration.
- The TSP API now supports generation of certIDs based on digests other than SHA-1.
- OCSP responses can now be included in CMS SignedData objects.
- The SipHash MAC algorithm has been added to the lightweight API and the provider.
- ISO9796-2 PSS signatures can now be initialised with a signature to allow the signer to deal with odd recovered message lengths on verification.
- The 4 DRBGs described in NIST SP 800-90A have been added to the prng package together with SecureRandom builders.
- Support has been added for OCB mode in the lightweight API.
- DSA version 2 parameter and key generation is now supported in the provider and lightweight API.
- A new interface Memoable has been added for objects that can copy in and out their state. The digest classes now support this. A special class NonMemoableDigest has been added which hides the Memoable interface where it should not be available.
- TDEA is now recognised as an alias for DESede.
- A new package org.bouncycastle.crypto.ec has been introduced to the light wieght API with a range of EC based cryptographic operators.
- The OpenPGP API now supports password changing on V3 keys if the appropriate PBEKeyEncryptor is used.
- The OpenPGP API now supports password changing on secret key rings where only the private keys for the subkeys have been exported.
- Support has been added to the lightweight API for RSA-KEM and ECIES-KEM.
- Support has been added for NIST SP 800-38D - GMAC to AES and other 128 bit block size algorithms.
- The org.bouncycastle.crypto.tls package has been extended to support client and server side TLS 1.1.
- The org.bouncycastle.crypto.tls package has been extended to support client and server side DTLS 1.0.
- A basic commitment package has been introduced into the lightweight API containing a digest based commitment scheme.
- It is now possible to set the NotAfter and NotBefore date in the CRMF CertificateRequestMessageBuilder class.

### 2.43.4 Notes

- The NTRU implementation has been moved into the org.bouncycastle.pqc package hierarchy.
- The change to PEMParser to support explicit EC curves is not backward compatible. If you run into a named curve you need to use org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID() to look the curve up if required.

<a id="r1rv48"></a>

### 2.44.1 Version

Release: 1.48\
Date: 2013, February 10

### 2.44.2 Defects Fixed

- Occasional key compatibility issues in IES due to variable length keys have been fixed.
- PEMWriter now recognises the new PKCS10CertificationRequest object.
- The provider implementation for RSA now resets when the init method is called.
- SignerInformation has been rewritten to better support signers without any associated signed attributes.
- An issue with an incorrect version number of SignedData associated with the use of SubjectKeyIdentifiers has now been fixed.
- An issue with the equals() check in BCStrictStyle has been fixed.
- The BC SSL implementation has been modified to deal with the "Lucky Thirteen" attack.
- A regression in 1.47 which prevented key wrapping with regular symmetric PBE algorihtms has been fixed.

### 2.44.3 Additional Features and Functionality

- IES now supports auto generation of ephemeral keys in both the JCE and the lightweight APIs.
- A new class PEMParser has been added to return the new CertificateHolder and Request objects introduced recently.
- An implementation of Password Authenticated Key Exchange by Juggling (J-PAKE) has now been added to the lightweight API.
- Support has now been added for the DSTU-4145-2002 to the lightweight API and the provider.
- The BC X509Certificate implementation now provides support for the JCA methods X509Certificate.getSubjectAlternativeNames() and X509Certificate.getIssuerAlternativeNames().
- PEMReader can now be configured to support different providers for encyrption and public key decoding.
- Some extra DSA OIDs have been added to the supported list for the provider.
- The BC provider will now automatically try to interpret other provider software EC private keys. It is no longer necessary to use a KeyFactory for conversion.
- A new provider, the BCPQC (for BC Post Quantum) provider has been added with support for the Rainbow signature algorithm and the McEliece family of encryption algorithms.
- Support has been added for the SHA3 family of digests to both the provider and the lightweight API.
- T61String now uses UTF-8 encoding by default rather than a simple 8 bit transform.

<a id="r1rv47"></a>

### 2.45.1 Version

Release: 1.47\
Date: 2012, March 30

### 2.45.2 Defects Fixed

- OpenPGP ID based certifications now support UTF-8. Note: this may mean that some old certifications no longer validate - if this happens a retry can be added using by converting the ID using Strings.fromByteArray(Strings.toByteArray(id)) - this will strip out the top byte in each character.
- IPv4/IPv6 parsing in CIDR no longer assumes octet boundaries on a mask.
- The CRL PKIX routines will now only rebuild the CRL as a last resort when looking for the certificate issuer.
- The DEK-Info header in PEM generation was lower case. It is now upper case in accordance with RFC 1421.
- An occasional issue causing an OutOfMemoryException for PGP compressed data generation has now been fixed.
- An illegal argument exception that could occur with multi-valued RDNs in the X509v3CertificateBuilder has been fixed.
- Shared secret calculation in IES could occasionally add a leading zero byte. This has been fixed.
- PEMReader would choke on a private key with an empty password. This has been fixed.
- The default MAC for a BKS key store was 2 bytes, this has been upgraded to 20 bytes. This fix is now also referred to in CVE-2018-5382.
- BKS key store loading no longer freezes on negative iteration counts.
- A regression in 1.46 which prevented parsing of PEM files with extra text at the start has been fixed.
- CMS secret key generation now attempts to stop use of invalid lengths with OIDs that predefine a key length.
- Check of DH parameter L could reject some valid keys. This is now fixed.

### 2.45.3 Additional Features and Functionality

- Support is now provided via the RepeatedKey class to enable IV only re-initialisation in the JCE layer. The same effect can be acheived in the light weight API by using null as the key parameter when creating a ParametersWithIV object.
- CRMF now supports empty poposkInput.
- The OpenPGP API now supports operator based interfaces for most operations and lightweight implementations have been added for JCE related functionality.
- JcaSignerId and JceRecipientId will now match on serial number, issuer, and the subject key identifier if it's available.
- CMS Enveloped and AuthenticatedData now support OriginatorInfo.
- NTRU encryption and signing is now provided in the lightweight source and the ext version of the provider.
- There is now API support for Extended Access Control (EAC).
- The performance of CertPath building and validation has been improved.
- The TLS Java Client API has been updated to make support for GSI GSSAPI possible.
- Support for ECDSA_fixed_ECDH authentication has been added to the TLS client.
- Support for the Features signature sub-packet has been added to the PGP API.
- The number of lightweight operators for PGP and CMS/SMIME has been increased.
- Classes involved in CRL manipulation have been rewritten to reduce memory requirements for handling and parsing extremely large CRLs.
- RFC 5751 changed the definition of the micalg parameters defined in RFC 3851. The SMIMESignedGenerator is now up to date with the latest micalg parameter set and a constructor has been added to allow the old micalg parameter set to be used.
- An operator based framework has been added for processing PKCS#8 and PKCS#12 files.
- The J2ME lcrypto release now includes higher level classes for handling PKCS, CMS, CRMF, CMP, EAC, OpenPGP, and certificate generation.

### 2.45.4 Other notes

Okay, so we have had to do another release. The issue we have run into is that we probably didn't go far enough in 1.46, but we are now confident that moving from this release to 2.0 should be largely just getting rid of deprecated methods. While this release does change a lot it is relatively straight forward to do a port and we have a [porting guide](https://github.com/bcgit/bc-java/wiki/Porting-From-Earlier-BC-Releases-to-1.47-and-Later) which explains the important ones. The area there has been the most change in is the ASN.1 library which was in bad need of a rewrite after 10 years of patching. On the bright side the rewrite did allow us to eliminate a few problems and bugs in the ASN.1 library, so we have some hope anyone porting to it will also have similar benefits. As with 1.46 the other point of emphasis has been making sure interface support is available for operations across the major APIs, so the lightweight API or some local role your own methods can be used instead for doing encryption and signing.

<a id="r1rv46"></a>

### 2.46.1 Version

Release: 1.46\
Date: 2011, February 23

### 2.46.2 Defects Fixed

- An edge condition in ECDSA which could result in an invalid signature has been fixed.
- Exhaustive testing has been performed on the ASN.1 parser, eliminating another potential OutOfMemoryException and several escaping run time exceptions.
- BC generated certificates generated different hashCodes from other equivalent implementations. This has been fixed.
- Parsing an ESSCertIDv2 would fail if the object did not include an IssuerSerialNumber. This has been fixed.
- DERGeneralizedTime.getDate() would produce incorrect results for fractional seconds. This has been fixed.
- PSSSigner would produce incorrect results if the MGF digest and content digest were not the same. This has been fixed.

### 2.46.3 Additional Features and Functionality

- A null genTime can be passed to TimeStampResponseGenerator.generate() to generate timeNotAvailable error responses.
- Support has been added for reading and writing of openssl PKCS#8 encrypted keys.
- New streams have been added for supporting general creation of PEM data, and allowing for estimation of output size on generation. Generators have been added for some of the standard OpenSSL objects.
- CRL searching for CertPath validation now supports the optional algorithm given in Section 6.3.3 of RFC 5280, allowing the latest CRL to be used for a set time providing the certificate is unexpired.
- AES-CMAC and DESede-CMAC have been added to the JCE provider.
- Support for CRMF (RFC 4211) and CMP (RFC 4210) has been added.
- BufferedBlockCipher will now always reset after a doFinal().
- Support for CMS TimeStampedData (RFC 5544) has been added.
- JCE EC keypairs are now serialisable.
- TLS now supports client-side authentication.
- TLS now supports compression.
- TLS now supports ECC cipher suites (RFC 4492).
- PGP public subkeys can now be separately decoded and encoded.
- An IV can now be passed to an ISO9797Alg3Mac.

### 2.46.4 Other notes

Baring security patches we expect 1.46 will be the last of the 1.\* releases. The next release of BC will be version 2.0. For this reason a lot of things in 1.46 that relate to CMS have been deprecated and new methods have been added to the CMS and certificate handling APIs which provide greater flexibility in how digest and signature algorithms get used. It is now possible to use the lightweight API or a simple custom API with CMS and for certificate generation. In addition a lot of methods and some classes that were deprecated for reasons of been confusing, or in some cases just plan wrong, have been removed.

So there are four things useful to know about this release:

- It's not a simple drop in like previous releases, if you wish migrate to it you will need to recompile your application.
- If you avoid deprecated methods it should be relatively painless to move to version 2.0
- The X509Name class will utlimately be replacde with the X500Name class, the getInstance() methods on both these classes allow conversion from one type to another.
- The org.bouncycastle.cms.RecipientId class now has a collection of subclasses to allow for more specific recipient matching. If you are creating your own recipient ids you should use the constructors for the subclasses rather than relying on the set methods inherited from X509CertSelector. The dependencies on X509CertSelector and CertStore will be removed from the version 2 CMS API.

<a id="r1rv45"></a>

### 2.47.1 Version

Release: 1.45\
Date: 2010, January 12

### 2.47.2 Defects Fixed

- OpenPGP now supports UTF-8 in file names for literal data.
- The ASN.1 library was losing track of the stream limit in a couple of places, leading to the potential of an OutOfMemoryError on a badly corrupted stream. This has been fixed.
- The provider now uses a privileged block for initialisation.
- JCE/JCA EC keys are now serialisable.

### 2.47.3 Additional Features and Functionality

- Support for EC MQV has been added to the light weight API, provider, and the CMS/SMIME library.

### 2.47.4 Security Advisory

- This version of the provider has been specifically reviewed to eliminate possible timing attacks on algorithms such as GCM and CCM mode.

<a id="r1rv44"></a>

### 2.48.1 Version

Release: 1.44\
Date: 2009, October 9

### 2.48.2 Defects Fixed

- The reset() method in BufferedAsymmetricBlockCipher is now fully clearing the buffer.
- Use of ImplicitlyCA with KeyFactory and Sun keyspec no longer causes NullPointerException.
- X509DefaultEntryConverter was not recognising telephone number as a PrintableString field. This has been fixed.
- The SecureRandom in the J2ME was not using a common seed source, which made cross seeeding of SecureRandom's impossible. This has been fixed.
- Occasional uses of "private final" on methods were causing issues with some J2ME platforms. The use of "private final" on methods has been removed.
- NONEwithDSA was not resetting correctly on verify() or sign(). This has been fixed.
- Fractional seconds in a GeneralisedTime were resulting in incorrect date conversions if more than 3 decimal places were included due to the Java date parser. Fractional seconds are now truncated to 3 decimal places on conversion.
- The micAlg in S/MIME signed messages was not always including the hash algorithm for previous signers. This has been fixed.
- SignedMailValidator was only including the From header and ignoring the Sender header in validating the email address. This has been fixed.
- The PKCS#12 keystore would throw a NullPointerException if a null password was passed in. This has been fixed.
- CertRepMessage.getResponse() was attempting to return the wrong underlying field in the structure. This has been fixed.
- PKIXCertPathReviewer.getTrustAnchor() could occasionally cause a null pointer exception or an exception due to conflicting trust anchors. This has been fixed.
- Handling of explicit CommandMap objects with the generation of S/MIME messages has been improved.

### 2.48.3 Additional Features and Functionality

- PEMReader/PEMWriter now support encrypted EC keys.
- BC generated EC private keys now include optional fields required by OpenSSL.
- Support for PSS signatures has been added to CMS and S/MIME.
- CMS processing will attempt to recover if there is no AlgorithmParameters object for a provider and use an IvParameterSpec where possible.
- CertificateID always required a provider to be explicitly set. A null provider is now interpreted as a request to use the default provider.
- SubjectKeyIdentifier now supports both methods specified in RFC 3280, section 4.2.1.2 for generating the identifier.
- Performance of GCM mode has been greatly improved (on average 10x).
- The BC provider has been updated to support the JSSE in providing ECDH.
- Support for mac lengths of 96, 104, 112, and 120 bits has been added to existing support for 128 bits in GCMBlockCipher.
- General work has been done on trying to propagate exception causes more effectively.
- Support for loading GOST 34.10-2001 keys has been improved in the provider.
- Support for raw signatures has been extended to RSA and RSA-PSS in the provider. RSA support can be used in CMSSignedDataStreamGenerator to support signatures without signed attributes.

<a id="r1rv43"></a>

### 2.49.1 Version

Release: 1.43\
Date: 2009, April 13

### 2.49.2 Defects Fixed

- Multiple countersignature attributes are now correctly collected.
- Two bugs in HC-128 and HC-256 related to sign extension and byte swapping have been fixed. The implementations now pass the latest ecrypt vector tests.
- X509Name.hashCode() is now consistent with equals.

### 2.49.3 Security Advisory

- The effect of the sign extension bug was to decrease the key space the HC-128 and HC-256 ciphers were operating in and the byte swapping inverted every 32 bits of the generated stream. If you are using either HC-128 or HC-256 you must upgrade to this release.

<a id="r1rv42"></a>

### 2.50.1 Version

Release: 1.42\
Date: 2009, March 16

### 2.50.2 Defects Fixed

- A NullPointer exception which could be result from generating a diffie-hellman key has been fixed.
- CertPath validation could occasionally mistakenly identify a delta CRL. This has been fixed.
- '=' inside a X509Name/X509Principal was not being properly escaped. This has been fixed.
- ApplicationSpecific ASN.1 tags are now recognised in BER data. The getObject() method now handles processing of arbitrary tags.
- X509CertStoreSelector.getInstance() was not propagating the subjectAlternativeNames attribute. This has been fixed.
- Use of the BC PKCS#12 implementation required the BC provider to be registered explicitly with the JCE. This has been fixed.
- OpenPGP now fully supports use of the Provider object.
- CMS now fully supports use of the Provider object.
- Multiplication by negative powers of two is fixed in BigInteger.
- OptionalValidity now encodes correctly.

### 2.50.3 Additional Features and Functionality

- Support for NONEwithECDSA has been added.
- Support for Grainv1 and Grain128 has been added.
- Support for EAC algorithms has been added to CMS/SMIME.
- Support for basic CMS AuthenticatedData to the CMS package.
- Jars are now packaged using pack200 for JDK1.5 and JDK 1.6.
- ASN1Dump now supports a verbose mode for displaying the contents of octet and bit strings.
- Support for the SRP-6a protocol has been added to the lightweight API.

<a id="r1rv41"></a>

### 2.51.1 Version

Release: 1.41\
Date: 2008, October 1

### 2.51.2 Defects Fixed

- The GeneralName String constructor now supports IPv4 and IPv6 address parsing.
- An issue with nested-multiparts with postamble for S/MIME that was causing signatures to fail verification has been fixed.
- ESSCertIDv2 encoding now complies with RFC 5035.
- ECDSA now computes correct signatures for oversized hashes when the order of the base point is not a multiple of 8 in compliance with X9.62-2005.
- J2ME SecureRandom now provides additional protection against predictive and backtracking attacks when high volumes of random data are generated.
- Fix to regression from 1.38: PKIXCertPathCheckers were not being called on intermediate certificates.
- Standard name "DiffieHellman" is now supported in the provider.
- Better support for equality tests for '#' encoded entries has been added to X509Name.

### 2.51.3 Additional Features and Functionality

- Camellia is now 12.5% faster than previously.
- A smaller version (around 8k compiled) of Camellia, CamelliaLightEngine has also been added.
- CMSSignedData generation now supports SubjectKeyIdentifier as well as use of issuer/serial.
- A CMSPBE key holder for UTF-8 keys has been added to the CMS API.
- Salt and iteration count can now be recovered from PasswordRecipientInformation.
- Methods in the OpenPGP, CMS, and S/MIME APIs which previously could only take provider names can now take providers objects as well (JDK1.4 and greater).
- Support for reading and extracting personalised certificates in PGP Secret Key rings has been added.

<a id="r1rv40"></a>

### 2.52.1 Version

Release: 1.40\
Date: 2008, July 12

### 2.52.2 Defects Fixed

- EAX mode ciphers were not resetting correctly after a doFinal/reset. This has been fixed.
- The SMIME API was failing to verify doubly nested multipart objects in signatures correctly. This has been fixed.
- Some boolean parameters to IssuingDistributionPoint were being reversed. This has been fixed.
- A zero length RDN would cause an exception in an X509Name. This has been fixed.
- Passing a null to ExtendedPKIXParameters.setTrustedACIssuers() would cause a NullPointerException. This has been fixed.
- CertTemplate was incorrectly encoding issuer and subject fields when set.
- hashCode() for X509CertificateObject was very poor. This has been fixed.
- Specifying a greater than 32bit length for a stream and relying on the default BCPGOutputStream resulted in corrupted data. This has been fixed.
- PKCS7Padding validation would not fail if pad length was 0. This has been fixed.
- javax.crypto classes no longer appear in the JDK 1.3 provider jar.
- Signature creation time was not being properly initialised in new V4 PGP signature objects although the encoding was correct. This has been fixed.
- The '+' character can now be escaped or quoted in the constructor for X509Name, X509Prinicipal.
- Fix to regression from 1.38: PKIXCertPathValidatorResult.getPublicKey was returning the wrong public key when the BC certificate path validator was used.

### 2.52.3 Additional Features and Functionality

- Galois/Counter Mode (GCM) has been added to the lightweight API and the JCE provider.
- SignedPublicKeyAndChallenge and PKCS10CertificationRequest can now take null providers if you need to fall back to the default provider mechanism.
- The TSP package now supports validation of responses with V2 signing certificate entries.
- Unnecessary local ID attributes on certificates in PKCS12 files are now automatically removed.
- The PKCS12 store types PKCS12-3DES-3DES and PKCS12-DEF-3DES-3DES have been added to support generation of PKCS12 files with both certificates and keys protected by 3DES.

### 2.52.4 Additional Notes

- Due to problems for some users caused by the presence of the IDEA algorithm, an implementation is no longer included in the default signed jars. Only the providers of the form bcprov-ext-\*-\*.jar now include IDEA.

<a id="r1rv39"></a>

### 2.53.1 Version

Release: 1.39\
Date: 2008, March 29

### 2.53.2 Defects Fixed

- A bug causing the odd NullPointerException has been removed from the LocalizedMessage class.
- IV handling in CMS for the SEED and Camellia was incorrect. This has been fixed.
- ASN.1 stream parser now throws exceptions for unterminated sequences.
- EAX mode was not handling non-zero offsetted data correctly and failing. This has been fixed.
- The BC X509CertificateFactory now handles multiple certificates and CRLs in streams that don't support marking.
- The BC CRL implementation could lead to a NullPointer exception being thrown if critical extensions were missing. This has been fixed.
- Some ASN.1 structures would cause a class cast exception in AuthorityKeyIdentifier. This has been fixed.
- The CertID class used by the TSP library was incomplete. This has been fixed.
- A system property check in PKCS1Encoding to cause a AccessControlException under some circumstances. This has been fixed.
- A decoding issue with a mis-identified tagged object in CertRepMessage has been fixed.
- \\# is now properly recognised in the X509Name class.

### 2.53.3 Additional Features and Functionality

- Certifications associated with user attributes can now be created, verified and removed in OpenPGP.
- API support now exists for CMS countersignature reading and production.
- The TSP package now supports parsing of responses with V2 signing certificate entries.
- Lazy evaluation of DER sequences has been introduced to ASN1InputStream to allow support for larger sequences.
- KeyPurposeId class has been updated for RFC 4945.
- CertPath processing has been further extended to encompass the NIST CertPath evaluation suite.
- Initial support has been added for HP_CERTIFICATE_REQUEST in the TLS API.
- Providers for JDK 1.4 and up now use SignatureSpi directly rather than extending Signature. This is more in track with the way dynamic provider selection now works.
- PGP example programs now handle blank names in literal data objects.
- The ProofOfPossession class now better supports the underlying ASN.1 structure.
- Support has been added to the provider for the VMPC MAC.

<a id="r1rv38"></a>

### 2.54.1 Version

Release: 1.38\
Date: 2007, November 7

### 2.54.2 Defects Fixed

- SMIME signatures containing non-standard quote-printable data could be altered by SMIME encryption. This has been fixed.
- CMS signatures that do not use signed attributes were vulnerable to one of Bleichenbacher's RSA signature forgery attacks. This has been fixed.
- The SMIMESignedParser(Part) constructor was not producing a content body part that cleared itself after writeTo() as indicated in the JavaDoc. This has been fixed.
- BCPGInputStream now handles data blocks in the 2\*\*31-\>2\*\*32-1 range.
- A bug causing second and later encrypted objects to be ignored in KeyBasedFileProcessor example has been fixed.
- Value of the TstInfo.Tsa field is now directly accessible from TimeStampTokenInfo.
- Generating an ECGOST-3410 key using an ECGenParameterSpec could cause a ClassCastException in the key generator. This has been fixed.
- Use of the parameters J and L in connection with Diffie-Hellman parameters in the light weight API was ambiguous and confusing. This has been dealt with.
- Some entities were not fully removed from a PKCS#12 file when deleted due to case issues. This has been fixed.
- Overwriting entities in a PKCS#12 file was not fully compliant with the JavaDoc for KeyStore. This has been fixed.
- TlsInputStream.read() could appear to return end of file when end of file had not been reached. This has been fixed.

### 2.54.3 Additional Features and Functionality

- Buffering in the streaming CMS has been reworked. Throughput is now usually higher and the behaviour is more predictable.
- It's now possible to pass a table of hashes to a CMS detached signature rather than having to always pass the data.
- Classes supporting signature policy and signer attributes have been added to the ASN.1 ESS/ESF packages.
- Further work has been done on optimising memory usage in ASN1InputStream. In some cases memory usage has been reduced to 25% of previous.
- Pre-existing signers can now be added to the SMIMESignedGenerator.
- Support has been added to the provider for the VMPC stream cipher.
- CertPathReviewer has better handling for problem trust anchors.
- Base64 encoder now does initial size calculations to try to improve resource usage.

<a id="r1rv37"></a>

### 2.55.1 Version

Release: 1.37\
Date: 2007, June 15

### 2.55.2 Defects Fixed

- The ClearSignedFileProcessor example for OpenPGP did not take into account trailing white space in the file to be signed. This has been fixed.
- A possible infinite loop in the CertPathBuilder and SignedMailValidator have been removed.
- Requesting DES, DESede, or Blowfish keys using regular Diffie-Hellman now returns the same length keys as the regular JCE provider.
- Some uncompressed EC certificates were being interpreted as compressed and causing an exception. This has been fixed.
- Adding a CRL with no revocations on it to the CRL generator could cause an exception to be thrown. This has been fixed.
- Using the default JDK provider with the CMS library would cause exceptions in some circumstances. This has been fixed.
- BC provider DSAKeys are now serializable.
- Using only a non-sha digest in S/MIME signed data would produce a corrupt MIME header. This has been fixed.
- The default private key length in the lightweght API for generated DiffieHellman parameters was absurdly small, this has been fixed.
- Cipher.getParameters() for PBEwithSHAAndTwofish-CBC was returning null after intialisation. This has been fixed.

### 2.55.3 Additional Features and Functionality

- The block cipher mode CCM has been added to the provider and light weight API.
- The block cipher mode EAX has been added to the provider and light weight API.
- The stream cipher HC-128 and HC-256 has been added to the provider and lightwieght API.
- The stream cipher ISAAC has been added to the lightweight API.
- Support for producing and parsing notation data signature subpackets has been added to OpenPGP.
- Support for implicit tagging has been added to DERApplicationSpecific.
- CMS better supports basic Sun provider.
- A full set of SEC-2 EC curves is now provided in the SEC lookup table.
- Specifying a null provider in CMS now always uses the default provider, rather than causing an exception.
- Support has been added to the OpenPGP API for parsing experimental signatures
- CertPath validator now handles inherited DSA parameters and a wider range of name constraints.
- Further work has been done on improving the performance of ECDSA - it is now about two to six times faster depending on the curve.
- The Noekeon block cipher has been added to the provider and the lightweight API.
- Certificate generation now supports generation of certificates with an empty Subject if the subjectAlternativeName extension is present.
- The JCE provider now supports RIPEMD160withECDSA.

<a id="r1rv36"></a>

### 2.56.1 Version

Release: 1.36\
Date: 2007, March 16

### 2.56.2 Defects Fixed

- DSA key generator now checks range and keysize.
- Class loader issues with i18n classes should now be fixed.
- X.500 name serial number value now output as unambiguous long form SERIALNUMBER
- The fix for multipart messages with mixed content-transfer-encoding in 1.35 caused a regression for processing some messages with embedded multiparts that contained blank lines of preamble text - this should now be fixed.
- Another regression which sometimes affected the SMIMESignedParser has also been fixed.
- SharedFileInputStream compatibility issues with JavaMail 1.4 have been addressed.
- JDK 1.5 and later KeyFactory now accepts ECPublicKey/ECPrivateKey to translateKey.
- JDK 1.5 and later KeyFactory now produces ECPublicKeySpec/ECPrivateKeySpec on getKeySpec.
- Some surrogate pairs were not assembled correctly by the UTF-8 decoder. This has been fixed.
- Alias resolution in PKCS#12 is now case insensitive.

### 2.56.3 Additional Features and Functionality

- CMS/SMIME now supports basic EC KeyAgreement with X9.63.
- CMS/SMIME now supports RFC 3211 password based encryption.
- Support has been added for certificate, CRL, and certification request generation for the regular SHA algorithms with RSA-PSS.
- Further work has been done in speeding up prime number generation in the lightweight BigInteger class.
- Support for the SEED algorithm has been added to the provider and the lightweight API.
- Support for the Salsa20 algorithm has been added to the provider and the lightweight API.
- CMS/SMIME now support SEED and Camellia
- A table of TeleTrusT curves has been added.
- CMSSignedData creation and Collection CertStore now preserves the order of certificates/CRls if the backing collection is ordered.
- CMS Signed objects now use BER encoding for sets containing certificates and CRLs, allowing specific ordering to be specified for the objects contained.
- CMS enveloped now works around providers which throw UnsupportedOperationException if key wrap is attempted.
- DSASigner now handles long messages. SHA2 family digest support for DSA has been added to the provider.

<a id="r1rv35"></a>

### 2.57.1 Version

Release: 1.35\
Date: 2006, December 16

### 2.57.2 Defects Fixed

- Test data files are no longer in the provider jars.
- SMIMESignedParser now handles indefinite length data in SignerInfos.
- Under some circumstances the SMIME library was failing to canonicalize mixed-multipart data correctly. This has been fixed.
- The l parameter was being ignored for the DH and ElGamal key generation. This has been fixed.
- The ASN1Sequence constructor for OtherRecipientInfo was broken. It has been fixed
- Regression - DN fields SerialNumber and Country were changed to encode as UTF8String in 1.34 in the X509DefaultEntryConverter, these now encode as PrintableString.
- CMSSignedData.replaceSigners() was not replacing the digest set as well as the signers. This has been fixed.
- DERGeneralizedTime produced a time string without a GMT offset if they represented local time. This has been fixed.
- Some temp files were still being left on Windows by the SMIME library. All of the known problems have been fixed.
- Comparing ASN.1 object for equality would fail in some circumstances. This has been fixed.
- The IESEngine could incorrectly encrypt data when used in block cipher mode. This has been fixed.
- An error in the encoding of the KEKRecipientInfo has been fixed. Compatability warning: this may mean that versions of BC mail prior to 1.35 will have trouble processing KEK messages produced by 1.35 or later.

### 2.57.3 Additional Features and Functionality

- Further optimisations to elliptic curve math libraries.
- API now incorporates a CertStore which should be suitable for use with LDAP.
- The streaming ASN.1 API is now integrated into the base one, the sasn1 package has been deprecated.
- The OpenPGP implementation now supports SHA-224 and BZIP2.
- The OpenPGP implementation now supports SHA-1 checksumming on secret keys.
- The JCE provider now does RSA blinding by default.
- CMSSignedDataParser now provides methods for replacing signers and replacing certificates and CRLs.
- A generic store API has been added to support CRLs, Certificates and Attribute certificates.
- The CMS/SMIME API now supports inclusion and retrieval of version 2 attribute certificates.
- Support for generating CertificationRequests and Certificates has been added for GOST-3410-2001 (ECGOST)
- CMS/SMIME now support ECGOST
- Basic BER Octet Strings now encode in a canonical fashion by default.
- DERUTCTime can now return Date objects
- Validating constructors have been added to DERPrintableString, DERIA5String, and DERNumericString.
- A lightweight API for supporting TLS has been added.
- Implementations of the TEA and XTEA ciphers have been added to the light weight API and the provider.
- PEMReader now supports OpenSSL ECDSA key pairs.
- PGP packet streams can now be closed off using close() on the returned stream as well as closing the generator.

<a id="r1rv34"></a>

### 2.58.1 Version

Release: 1.34\
Date: 2006, October 2

### 2.58.2 Defects Fixed

- Endianess of integer conversion in KDF2BytesGenerator was incorrect. This has been fixed.
- Generating critical signature subpackets in OpenPGP would result in a zero packet tag. This has been fixed.
- Some flags in PKIFailure info were incorrect, and the range of values was incomplete. The range of values has been increased and the flags corrected.
- The helper class for AuthorityKeyExtension generation was including the subject rather than the issuer DN of the CA certificate. This has been fixed.
- SMIMESignedParser now avoids JavaMail quoted-printable recoding issue.
- Verification of RSA signatures done with keys with public exponents of 3 was vunerable to Bleichenbacher's RSA signature forgery attack. This has been fixed.
- PGP Identity strings were only being interpreted as ASCII rather than UTF-8. This has been fixed.
- CertificateFactory.generateCRLs now returns a Collection rather than null.

### 2.58.3 Additional Features and Functionality

- An ISO18033KDFParameters class had been added to support ISO18033 KDF generators.
- An implemention of the KDF1 bytes generator algorithm has been added.
- An implementation of NaccacheStern encryption has been added to the lightweight API.
- X509V2CRLGenerator can now be loaded from an existing CRL.
- The CMS enveloped data generators will now attempt to use the default provider for encryption if the passed in provider can only handle key exchange.
- OpenPGP file processing has been substantially speeded up.
- The PKCS1Encoder would accept PKCS1 packets which were one byte oversize. By default this will now cause an error. However, as there are still implementations which still produce such packets the older behaviour can be turned on by setting the VM system property org.bouncycastle.pkcs1.strict to false before creating an RSA cipher using PKCS1 encoding.
- A target has been added to the bc-build.xml to zip up the source code rather than leaving it in a directory tree. The build scripts now run this target by default.
- Use of toUpperCase and toLowerCase has been replaced with a locale independent converter where appropriate.
- Support for retrieving the issuers of indirect CRLs has been added.
- Classes for doing incremental path validation of PKIX cert paths have been added to the X.509 package and S/MIME.
- Locale issues with String.toUpperCase() have now been worked around.
- Optional limiting has been added to ASN1InputStream to avoid possible OutOfMemoryErrors on corrupted streams.
- Support has been added for SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, and SHA512withECDSA for the generation of signatures, certificates, CRLs, and certification requests.
- Performance of the prime number generation in the BigInteger library has been further improved.
- In line with RFC 3280 section 4.1.2.4 DN's are now encoded using UTF8String by default rather than PrintableString.

### 2.58.4 Security Advisory

- If you are using public exponents with the value three you \*must\* upgrade to this release, otherwise it will be possible for attackers to exploit some of Bleichenbacher's RSA signature forgery attacks on your applications.

<a id="r1rv33"></a>

### 2.59.1 Version

Release: 1.33\
Date: 2006, May 3

### 2.59.2 Defects Fixed

- OCSPResponseData was including the default version in its encoding. This has been fixed.
- BasicOCSPResp.getVersion() would throw a NullPointer exception if called on a default version response. This has been fixed.
- Addition of an EC point under Fp could result in an ArithmeticException. This has been fixed.
- The n value for prime192v2 was incorrect. This has been fixed.
- ArmoredInputStream was not closing the underlying stream on close. This has been fixed.
- Small base64 encoded strings with embedded white space could decode incorrectly using the Base64 class. This has been fixed.

### 2.59.3 Additional Features and Functionality

- The X509V2CRLGenerator now supports adding general extensions to CRL entries.
- A RoleSyntax implementation has been added to the x509 ASN.1 package, and the AttributeCertificateHolder class now support the IssuerSerial option.
- The CMS API now correctly recognises the OIW OID for DSA with SHA-1.
- DERUTF8String now supports surrogate pairs.

<a id="r1rv32"></a>

### 2.60.1 Version

Release: 1.32\
Date: 2006, March 27

### 2.60.2 Defects Fixed

- Further work has been done on RFC 3280 compliance.
- The ASN1Sequence constructor for SemanticsInformation would sometimes throw a ClassCastException on reconstruction an object from a byte stream. This has been fixed.
- The SharedInputStream.read(buf, 0, len) method would return 0 at EOF, rather than -1. This has been fixed.
- X9FieldElement could fail to encode a Fp field element correctly. This has been fixed.
- The streaming S/MIME API was occasionally leaving temporary files around. The SIMEUtil class responsible for creating the files now returns a FileBackedMimeBodyPart object which has a dispose method on it which should allow removal of the file backing the body part.
- An encoding defect in EnvelopedData generation in the CMS streaming, S/MIME API has been fixed.
- DER constructed octet strings could cause exceptions in the streaming ASN.1 library. This has been fixed.
- Several compatibility issues connected with EnvelopedData decoding between the streaming CMS library and other libraries have been fixed.
- JDK 1.4 and earlier would sometimes encode named curve parameters explicitly. This has been fixed.
- An incorrect header for SHA-256 OpenPGP clear text signatures has been fixed.
- An occasional bug that could result in invalid clear text signatures has been fixed.
- OpenPGP clear text signatures containing '\r' as line separators were not being correctly canonicalized. This has been fixed.

### 2.60.3 Additional Features and Functionality

- The ASN.1 library now includes classes for the ICAO Electronic Passport.
- Support has been added to CMS and S/MIME for ECDSA.
- Support has been added for the SEC/NIST elliptic curves.
- Support has been added for elliptic curves over F2m.
- Support has been added for repeated attributes in CMS and S/MIME messages.
- A wider range of RSA-PSS signature types is now supported for CRL and Certificate verification.

### 2.60.4 Possible compatibility issue

- Previously elliptic curve keys and points were generated with point compression enabled by default. Owing to patent issues in some jurisdictions, they are now generated with point compression disabled by default.

<a id="r1rv31"></a>

### 2.61.1 Version

Release: 1.31\
Date: 2005, December 29

### 2.61.2 Defects Fixed

- getCriticalExtensionOIDs on an X.509 attribute certificate was returning the non-critical set. This has been fixed.
- Encoding uncompressed ECDSA keys could occasionally introduce an extra leading zero byte. This has been fixed.
- Expiry times for OpenPGP master keys are now recognised across the range of possible certifications.
- PGP 2 keys can now be decrypted by the the OpenPGP library.
- PGP 2 signature packets threw an exception on trailer processing. This has been been fixed.
- Attempting to retrieve signature subpackets from an OpenPGP version 3 signature would throw a null pointer exception. This has been fixed.
- Another occasional defect in EC point encoding has been fixed.
- In some cases AttributeCertificateHolder.getIssuer() would return an empty array for attribute certificates using the BaseCertificateID. This has been fixed.
- OIDs with extremely large components would sometimes reencode with unnecessary bytes in their encoding. The optimal DER encoding will now be produced instead.

### 2.61.3 Additional Features and Functionality

- The SMIME package now supports the large file streaming model as well.
- Additional ASN.1 message support has been added for RFC 3739 in the org.bouncycastle.x509.qualified package.
- Support has been added for Mac algorithm 3 from ISO 9797 to both the lightweight APIs and the provider.
- The provider now supports the DESEDE64 MAC algorithm.
- CertPathValidator has been updated to better support path validation as defined in RFC 3280.

<a id="r1rv30"></a>

### 2.62.1 Version

Release: 1.30\
Date: 2005, September 18

### 2.62.2 Defects Fixed

- Whirlpool was calculating the wrong digest for 31 byte data and could throw an exception for some other data lengths. This has been fixed.
- AlgorithmParameters for IVs were returning a default of RAW encoding of the parameters when they should have been returning an ASN.1 encoding. This has been fixed.
- Base64 encoded streams without armoring could cause an exception in PGPUtil.getDecoderStream(). This has been fixed.
- PGPSecretKey.copyWithNewPassword() would incorrectly tag sub keys. This has been fixed.
- PGPSecretKey.copyWithNewPassword() would not handle the NULL algorithm. This has been fixed.
- Directly accessing the dates on an X.509 Attribute Certificate constructed from an InputStream would return null, not the date objects. This has been fixed.
- KEKIdentifier would not handle OtherKeyAttribute objects correctly. This has been fixed.
- GetCertificateChain on a PKCS12 keystore would return a single certificate chain rather than null if the alias passed in represented a certificate not a key. This has been fixed.

### 2.62.3 Additional Features and Functionality

- RSAEngine no longer assumes keys are byte aligned when checking for out of range input.
- PGPSecretKeyRing.removeSecretKey and PGPSecretKeyRing.insertSecretKey have been added.
- There is now a getter for the serial number on TimeStampTokenInfo.
- Classes for dealing with CMS objects in a streaming fashion have been added to the CMS package.
- PGPCompressedDataGenerator now supports partial packets on output.
- OpenPGP Signature generation and verification now supports SHA-256, SHA-384, and SHA-512.
- Both the lightweight API and the provider now support the Camellia encryption algorithm.

<a id="r1rv29"></a>

### 2.63.1 Version

Release: 1.29\
Date: 2005, June 27

### 2.63.2 Defects Fixed

- HMac-SHA384 and HMac-SHA512 were not IETF compliant. This has been fixed.
- The equals() method on ElGamalKeyParameters and DHKeyParameters in the lightweight API would sometimes return false when it should return true. This has been fixed.
- Parse error for OpenSSL style PEM encoded certificate requests in the PEMReader has been fixed.
- PGPPublicKey.getValidDays() now checks for the relevant signature for version 4 and later keys as well as using the version 3 key valid days field.
- ISO9796 signatures for full recovered messsages could incorrectly verify for similar messages in some circumstances. This has been fixed.
- The occasional problem with decrypting PGP messages containing compressed streams now appears to be fixed.

### 2.63.3 Additional Features and Functionality

- Support has been added for the OIDs and key generation required for HMac-SHA224, HMac-SHA256, HMac-SHA384, and HMac-SHA512.
- SignerInformation will used default implementation of message digest if signature provider doesn't support it.
- The provider and the lightweight API now support the GOST-28147-94 MAC algorithm.
- Headers are now settable for PGP armored output streams.

### 2.63.4 Notes

- The old versions of HMac-SHA384 and HMac-SHA512 can be invoked as OldHMacSHA384 and OldHMacSHA512, or by using the OldHMac class in the lightweight API.

<a id="r1rv28"></a>

### 2.64.1 Version

Release: 1.28\
Date: 2005, April 20

### 2.64.2 Defects Fixed

- Signatures on binary encoded S/MIME messages could fail to validate when correct. This has been fixed.
- getExtensionValue() on CRL Entries were returning the encoding of the inner object, rather than the octet string. This has been fixed.
- CertPath implementation now returns an immutable list for a certificate path.
- Generic sorting now takes place in the CertificateFactory.generateCertPath() rather than CertPathValidator.
- DERGeneralizedTime can now handle time strings with milli-seconds.
- Stateful CertPathCheckers were not being initialised in all cases, by the CertPathValidator. This has been fixed.
- PGPUtil file processing methods were failing to close files after processing. This has been fixed.
- A disordered set in a CMS signature could cause a CMS signature to fail to validate when it should. This has been fixed.
- PKCS12 files where both the local key id and friendly name were set on a certificate would not parse correctly. This has been fixed.
- Filetype for S/MIME compressed messages was incorrect. This has been fixed.
- BigInteger class can now create negative numbers from byte arrays.

### 2.64.3 Additional Features and Functionality

- S/MIME now does canonicalization on non-binary input for signatures.
- Micalgs for the new SHA schemes are now supported.
- Provided and lightweight API now support ISO 7816-4 padding.
- The S/MIME API now directly supports the creation of certificate management messages.
- The provider and the light weight API now support the cipher GOST-28147, the signature algorithms GOST-3410 (GOST-3410 94) and EC GOST-3410 (GOST-3410 2001), the message digest GOST-3411 and the GOST OFB mode (use GOFB).
- CMSSignedDataGenerator will used default implementation of message digest if signature provider doesn't support it.
- Support has been added for the creation of ECDSA certificate requests.
- The provider and the light weight API now support the WHIRLPOOL message digest.

### 2.64.4 Notes

- Patches for S/MIME binary signatures and canonicalization were actually applied in 1.27, but a couple of days after the release - if the class CMSProcessableBodyPartOutbound is present in the package org.bouncycastle.mail.smime you have the patched 1.27. We would recommend upgrading to 1.28 in any case as some S/MIME 3.1 recommendations have also been introduced for header creation.
- GOST private keys are probably not encoding correctly and can be expected to change.

<a id="r1rv27"></a>

### 2.65.1 Version

Release: 1.27\
Date: 2005, February 20

### 2.65.2 Defects Fixed

- Typos in the provider which pointed Signature algorithms SHA256WithRSA, SHA256WithRSAEncryption, SHA384WithRSA, SHA384WithRSAEncryption, SHA512WithRSA, and SHA512WithRSAEncryption at the PSS versions of the algorithms have been fixed. The correct names for the PSS algorithms are SHA256withRSAandMGF1, SHA384withRSAandMGF1, and SHA512withRSAandMGF1.
- X509CertificateFactory failed under some circumstances to reset properly if the input stream being passed to generateCertificate(s)() changed, This has been fixed.
- OpenPGP BitStrength for DSA keys was being calculated from the key's generator rather than prime. This has been fixed.
- Possible infinite loop in ASN.1 SET sorting has been removed.
- SHA512withRSAandMGF1 with a zero length salt would cause an exception if used with a 1024 bit RSA key. This has been fixed.
- Adding an Exporter to a PGPSubpacketVector added a Revocable instead. This has been fixed.
- AttributeCertificateIssuer.getPrincipal() could throw an ArrayStoreException. This has been fixed.
- CertPathValidator now guarantees to call any CertPathCheckers passed in for each certificate.
- TSP TimeStampToken was failing to validate time stamp tokens with the issuerSerial field set in the ESSCertID structure. This has been fixed.
- Path validation in environments with frequently updated CRLs could occasionally reject a valid path. This has been fixed.

### 2.65.3 Additional Features and Functionality

- Full support has been added for the OAEPParameterSpec class to the JDK 1.5 povider.
- Full support has been added for the PSSParameterSpec class to the JDK 1.4 and JDK 1.5 providers.
- Support for PKCS1 signatures for SHA-256, SHA-384, and SHA-512 has been added to CMS.
- PGPKeyRingCollection classes now support partial matching of user ID strings.
- This release disables the quick check on the IV for a PGP public key encrypted message in order to help prevent applications being vunerable to oracle attacks.
- The CertPath support classes now support PKCS #7 encoding.
- Point compression can now be turned off when encoding elliptic curve keys.

### 2.65.4 Changes that may affect compatibility

- org.bouncycastle.jce.interfaces.ElGamalKey.getParams() has been changed to getParameters() to avoid clashes with a JCE interface with the same method signature.
- org.bouncycastle.jce.interfaces.ECKey.getParams() has been changed in JDK 1.5 to getParameters() to avoid clashes with a JCE interface with the same method signature. The getParams() method in pre-1.5 has been deprecated.
- SHA256WithRSAEncryption, SHA384WithRSAEncryption, SHA512WithRSAEncryption now refer to their PKCS #1 V1.5 implementations. If you were using these previously you should use SHA256WithRSAAndMGF1, SHA384WithRSAAndMGF1, or SHA512WithRSAAndMGF1.

<a id="r1rv26"></a>

### 2.66.1 Version

Release: 1.26\
Date: 2005, January 15

### 2.66.2 Defects Fixed

- The X.509 class UserNotice assumed some of the optional fields were not optional. This has been fixed.
- BCPGInputStream would break on input packets of 8274 bytes in length. This has been fixed.
- Public key fingerprints for PGP version 3 keys are now correctly calculated.
- ISO9796-2 PSS would sometimes throw an exception on a correct signature. This has been fixed.
- ASN1Sets now properly sort their contents when created from scratch.
- A bug introduced in the CertPath validation in the last release which meant some certificate paths would validate if they were invalid has been fixed.

### 2.66.3 Additional Features and Functionality

- Support for JDK 1.5 naming conventions for OAEP encryption and PSS signing has been added.
- Support for Time Stamp Protocol (RFC 3161) has been added.
- Support for Mozilla's PublicKeyAndChallenge key certification message has been added.
- OpenPGP now supports key rings containing GNU_DUMMY_S2K.
- Support for the new versions (JDK 1.4 and later) of PBEKeySpec has been added to the providers.
- PBEWithMD5AndRC2, PBEWithSHA1AndRC2 now generate keys rather than exceptions.
- The BigInteger implementation has been further optimised to take more advantage of the Montgomery number capabilities.

### 2.66.4 JDK 1.5 Changes

- The JDK 1.5 version of the provider now supports the new Elliptic Curve classes found in the java.security packages. Note: while we have tried to preserve some backwards compatibility people using Elliptic curve are likely to find some minor code changes are required when moving code from JDK 1.4 to JDK 1.5 as the java.security APIs have changed.

<a id="r1rv25"></a>

### 2.67.1 Version

Release: 1.25\
Date: 2004, October 1

### 2.67.2 Defects Fixed

- In some situations OpenPGP would overread when a stream had been broken up into partial blocks. This has been fixed.
- Explicitly setting a key size for RC4 in the CMS library would cause an exception. This has been fixed.
- getSignatures() on PGPPublicKey would throw a ClassCastException in some cases. This has been fixed.
- Encapsulated signed data was been generated with the wrong mime headers, this has been fixed.
- The isSignature method on PGPSecretKey now correctly identifies signing keys.
- An interoperability issue with DH key exchange between the Sun JCE provider and the BC provider, concerning sign bit expansion, has been fixed.
- The X509CertificateFactory would fail to reset correctly after reading an ASN.1 certificate chain. This has been fixed.
- CertPathValidator now handles unsorted lists of certs.
- The PGPSignatureGenerator would sometimes throw an exception when adding hashed subpackets. This has been fixed.
- Ordered equality in X509Name was not terminating as early as possible. This has been fixed.
- getBitStrength for PGPPublicKeys was returning the wrong value for ElGamal keys. This has been fixed.
- getKeyExpirationTime/getSignatureExpirationTime was returning a Date rather than a delta. This isn't meaningful as a Date and has been changed to a long.
- the crlIssuer field in DistributionPoint name was encoding/decoding incorrectly. This has been fixed.
- X509Name now recognises international characters in the input string and stores them as BMP strings.
- Parsing a message with a zero length body with SMIMESigned would cause an exception. This has been fixed.
- Some versions of PGP use zeros in the data stream rather than a replication of the last two bytes of the iv as specified in the RFC to determine if the correct decryption key has been found. The decryption classes will now cope with both.

### 2.67.3 Additional Features and Functionality

- Support for extracting signatures based on PGP user attributes has been added to PGPPublicKey.
- BCPGArmoredInputStream should cope with plain text files better.
- The OpenPGP library can now create indefinite length streams and handle packets greater than (2^32 - 1) in length.
- Direct support for adding SignerUserID and PrimaryUserID has been added to the PGPSignatureSubpacketGenerator.
- Support for ISO-9796-2/PSS has been added to the lightweight API.
- API support for extracting recovered messages from signatures that support message recovery has been added to the lightweight API.
- String value conversion in a DN being processed by X509Name is now fully configurable.
- It is now possible to create new versions of CMSSignedData objects without having to convert the original object down to its base ASN.1 equivalents.
- Support for adding PGP revocations and other key signatures has been added.
- Support for SHA-224 and SHA224withRSA has been added.
- Trailing bit complement (TBC) padding has been added.
- OID components of up to 2^63 bits are now supported.

<a id="r1rv24"></a>

### 2.68.1 Version

Release: 1.24\
Date: 2004, June 12

### 2.68.2 Defects Fixed

- OpenPGP Secret key rings now parse key rings with user attribute packets in them correctly.
- OpenPGP Secret key rings now parse key rings with GPG comment packets in them.
- X509Name and X509Principal now correctly handle BitStrings.
- OpenPGP now correctly recognises RSA signature only keys.
- When re-encoding PGP public keys taken off secret keys getEncoded would sometimes throw a NullPointerException. This has been fixed.
- A basic PKCS12 file with a single key and certificate, but no attributes, would cause a null pointer exception. This has been fixed.
- Signature verification now handles signatures where the parameters block is missing rather than NULL.
- Lightweight CBCBlockCipherMac was failing to add padding if padding was being explicitly provided and data length was a multiple of the block size. This has been fixed.
- ZIP compression in PGP was failing to compress data in many cases. This has been fixed.
- Signatures were occasionally produced with incorrect padding in their associated bit strings, this has been fixed.
- An encoding error introduced in 1.23 which affected generation of the KeyUsage extension has been fixed.

### 2.68.3 Additional Features and Functionality

- PKCS12 keystore now handles single key/certificate files without any attributes present.
- Support for creation of PGPKeyRings incorporating sub keys has been added.
- ZeroPadding for encrypting ASCII data has been added.

<a id="r1rv23"></a>

### 2.69.1 Version

Release: 1.23\
Date: 2004, April 10

### 2.69.2 Defects Fixed

- Reading a PGP Secret key file would sometimes cause a class cast exception. This has been fixed.
- PGP will now read SecretKeys which are encrypted with the null algorithm.
- PGP ObjectFactory will recognise Marker packets.
- BasicConstraints class now handles default empty sequences correctly.
- S2K Secret Key generation now supported in OpenPGP for keys greater than 160 bits, a bug causing it to occasionally generate the wrong key has been fixed.
- OpenPGP implementation can now read PGP 8 keys.
- Decoding issues with Secret Sub Keys should now be fixed.
- PGP would occasionally unpack ElGamal encrypted data incorrectly, this has been fixed.
- OCSP TBSRequest now uses abbreviated encoding if the default version is used.
- X509Name class will now print names with nested pairs in component sets correctly.
- RC4 now resets correctly on doFinal.

### 2.69.3 Additional Features and Functionality

- PGP V3 keys and V3 signature generation is now supported.
- Collection classes have been added for representing files of PGP public and secret keys.
- PEMReader now supports "RSA PUBLIC KEY".
- RipeMD256 and RipeMD320 have been added.
- Heuristic decoder stream has been added to OpenPGP which "guesses" how the input is constructed.
- ArmoredInputStream now recognises clear text signed files.
- ArmoredOutputStream now provides support for generating clear text signed files.
- Support has been added to CMS for RipeMD128, RipeMD160, and RipeMD256.
- Support for generating certification directly and editing PGP public key certifications has been added.
- Support has been added for modification detection codes to the PGP library.
- Examples have been rewritten to take advantage of the above.
- SMIMESigned can now covert data straight into a mime message.
- DERGeneralizedTime getTime() method now handles a broader range of input strings.

<a id="r1rv22"></a>

### 2.70.1 Version

Release: 1.22\
Date: 2004, February 7

### 2.70.2 Defects Fixed

- Generating DSA signatures with PGP would cause a class cast exception, this has been fixed.
- PGP Data in the 192 to 8383 byte length would sometimes be written with the wrong length header. This has been fixed.
- The certificate factory would only parse the first certificate in a PKCS7 object. This has been fixed.
- getRevocationReason() in RevokedStatus in OCSP would throw an exception for a non-null reason, rather than a null one. This has been fixed.
- PSS signature verification would fail approximately 0.5 % of the time on correct signatures. This has been fixed.
- Encoding of CRL Distribution Points now always works.

### 2.70.3 Additional Features and Functionality

- Additional methods for getting public key information have been added to the PGP package.
- Some support for user attributes and the image attribute tag has been added.
- Support for the AuthorityInformationAccess extension has been added.
- Support for ElGamal encryption/decryption has been added to the PGP package.

<a id="r1rv21"></a>

### 2.71.1 Version

Release: 1.21\
Date: 2003, December 6

### 2.71.2 Defects Fixed

- The CertPath validator would fail for some valid CRLs. This has been fixed.
- AES OIDS for S/MIME were still incorrect, this has been fixed.
- The CertPathBuilder would sometimes throw a NullPointerException looking for an issuer. This has been fixed.
- The J2ME BigInteger class would sometimes go into an infinite loop generating prime numbers. This has been fixed.
- DERBMPString.equals() would throw a class cast exception. This has been fixed.

### 2.71.3 Additional Features and Functionality

- PEMReader now handles public keys.
- OpenPGP/BCPG should now handle partial input streams. Additional methods for reading subpackets off signatures.
- The ASN.1 library now supports policy qualifiers and policy info objects.

<a id="r1rv20"></a>

### 2.72.1 Version

Release: 1.20\
Date: 2003, October 8

### 2.72.2 Defects Fixed

- BigInteger toString() in J2ME/JDK1.0 now produces same output as the Sun one.
- RSA would throw a NullPointer exception with doFinal without arguments. This has been fixed.
- OCSP CertificateID would calculate wrong issuer hash if issuer cert was not self signed. This has been fixed.
- Most of response generation in OCSP was broken. This has been fixed.
- The CertPath builder would sometimes go into an infinite loop on some chains if the trust anchor was missing. This has been fixed.
- AES OIDS were incorrect, this has been fixed.
- In some cases BC generated private keys would not work with the JSSE. This has been fixed.

### 2.72.3 Additional Features and Functionality

- Support for reading/writing OpenPGP public/private keys and OpenPGP signatures has been added.
- Support for generating OpenPGP PBE messages and public key encrypted messages has been added.
- Support for decrypting OpenPGP messages has been added.
- Addition of a Null block cipher to the light weight API.

<a id="r1rv19"></a>

### 2.73.1 Version

Release: 1.19\
Date: 2003, June 7

### 2.73.2 Defects Fixed

- The PKCS12 store would throw an exception reading PFX files that had attributes with no values. This has been fixed.
- RSA Private Keys would not serialise if they had PKCS12 bag attributes attached to them, this has been fixed.
- GeneralName was encoding OtherName as explicitly tagged, rather than implicitly tagged. This has been fixed.
- ASN1 parser would sometimes mistake an implicit null for an implicit empty sequence. This has been fixed.

### 2.73.3 Additional Features and Functionality

- S/MIME and CMS now support the draft standard for AES encryption.
- S/MIME and CMS now support setable key sizes for the standard algorithms.
- S/MIME and CMS now handle ARC4/RC4 encrypted messages.
- The CertPath validator now passes the NIST test suite.
- A basic OCSP implementation has been added which includes request generation and the processing of responses. Response generation is also provided, but should be treated as alpha quality code.
- CMS now attempts to use JCA naming conventions in addition to the OID name in order to find algorithms.

<a id="r1rv18"></a>

### 2.74.1 Version

Release: 1.18\
Date: 2003, February 8

### 2.74.2 Defects Fixed

- DESKeySpec.isParityAdjusted in the clean room JCE could go into an infinite loop. This has been fixed.
- The SMIME API would end up throwing a class cast exception if a MimeBodyPart was passed in containing a MimeMultipart. This is now fixed.
- ASN1InputStream could go into an infinite loop reading a truncated input stream. This has been fixed.
- Seeding with longs in the SecureRandom for the J2ME and JDK 1.0, only used 4 bytes of the seed value. This has been fixed.

### 2.74.3 Additional Features and Functionality

- The X.509 OID for RSA is now recognised by the provider as is the OID for RSA/OAEP.
- Default iv's for DES are now handled correctly in CMS.
- The ASN.1 classes have been updated to use the generic ASN1\* classes where possible.
- A constructor has been added to SMIMESigned to simplify the processing of "application/pkcs7-mime; smime-type=signed-data;" signatures.
- Diffie-Hellman key generation is now faster in environments using the Sun BigInteger library.

<a id="r1rv17"></a>

### 2.75.1 Version

Release: 1.17\
Date: 2003, January 8

### 2.75.2 Defects Fixed

- Reuse of an CMSSignedObject could occasionally result in a class cast exception. This has been fixed.
- The X.509 DistributionPointName occasionally encoded incorrectly. This has been fixed.
- BasicConstraints construction would break if an ASN.1 sequence was used with only the required parameter. This has been fixed.
- The DERObject constructor in OriginatorIdentifierOrKey was leaving the id field as null. This has been fixed.

### 2.75.3 Additional Functionality and Features

- RC2 now supports the full range of parameter versions and effective key sizes.
- CompressedData handling has been added to CMS/SMIME.
- The 1.4 version now allows X500Principles to be generated directly from CRLs.
- SMIME objects now support binary encoding. The number of signature types recognised has been increased.
- CMS can create signed objects with encapsulated data. Note: while this was been done we realised we could simplify things, we did and for the most part people won't notice, other than the occasional reference to CMSSignable will need to be replaced with CMSProcessable.
- X509Name and X509Principal now support forward and reverse X509Name to string conversion, with changeable lookup tables for converting OIDs into strings. Both classes also now allow the direction of encoding to be set when a string is converted as well as changeable lookup tables for string to OID conversion.

<a id="r1rv16"></a>

### 2.76.1 Version

Release: 1.16\
Date: 2002, November 30

### 2.76.2 Defects Fixed

- CRLS were only working for UTC time constructed Time objects, this has been fixed.
- KeyUsage and ReasonFlags sometimes encoded longer than necessary. This has been fixed.
- BER encoded sets are now recognised and dealt with.
- Encoding issues in CMS which were causing problems with backwards compatibility with older CMS/SMIME clients have been fixed.
- KeyFactory now allows for creation of RSAKey\*Spec classes.
- The X509CertSelector in the clean room CertPath API is now less likely to throw a NullPointerException at the wrong time.
- Macs now clone correctly in the clean room JCE.

### 2.76.3 Additional Functionality and Features

- PGPCFB support has been added to the provider and the lightweight API.
- There are now three versions of the AESEngine, all faster than before, with the largest footprint one being the fastest. The JCE AES now refers to the fastest.
- The 1.4 version of the library now allows for X500Principals to be generated directly from certificates.
- X509Name has been extended to parse numeric oids, "oid." oids, and to recognise the LDAP UID.
- Immutable sequences and sets have been introduced to the ASN.1 package.
- The SMIME/CMS ASN.1 base classes have been rewritten to reduce the size of the package for use with the lightweight API.
- The SMIME/CMS api's have been rewritten to allow them to take advantage of the Cert Path API, remove code suited to inclusion in the provider, and to support multiple recipients/signers.

<a id="r1rv15"></a>

### 2.77.1 Version

Release: 1.15\
Date: 2002, September 6

### 2.77.2 Defects Fixed

- The base string for the oids in asn1.x509.KeyPurposeId was incorrect. This has been fixed.
- MimeBodyParts in the SMIME Generator did not have their Content-Type properly set up after decryption. This has been fixed.
- If a X.509 certificate did not have all the keyUsage extension bits set, the provider wasn't padding the return value of the key usage extension to 8 booleans in length. This has been fixed.
- In some cases the simple BC keystore allowed overwriting of an alias with one of the same name. This has been fixed.
- The key schedule for RC5-64 was not always being calculated correctly. This has been fixed.
- On reset buffered blockcipher was only partially erasing the previous buffer. This has been fixed.
- All lightweight mac classes now do a reset on doFinal.
- ASN.1 object identifiers wouldn't encode the first byte correctly if the OID started with 2 and the second number was greater than 47. This has been fixed.
- If a key had PKCS9 attributes associated with it on storage they took precedence over the local alias used to add the key to the PKCS12 key store. The local name now takes precedence.
- ReasonFlags now correctly encodes.

### 2.77.3 Additional Functionality and Features

- The PKCS12 key store now handles key bags in encryptedData bags.
- The X509NameTokenizer now handles for '\\' and '"' characters.
- SMIME v2 compliance has been added. Use setVersion(2) in the generator classes.
- The ASN.1 library now supports ENUMERATED, UniversalString and the X.509 library support for CRLs now includes CRLReason, and some elements of CertificatePolicies.
- Both the provider and the lightweight library now support a basic SIC mode for block ciphers.

<a id="r1rv14"></a>

### 2.78.1 Version

Release: 1.14\
Date: 2002, June 17

### 2.78.2 Defects Fixed

- there was a bug in the BigInteger right shifting for \> 31 bit shifts. This has been fixed.
- x509 name had it's equality test based on the order of the directory elements, this has been fixed.
- the mode used with the RSA cipher in KeyTransRecipientInfoParser in the smime implementation was not compatible with the Sun JCE. This has been fixed.
- PKCS7 SignedData now supports single length signing chains.
- When a root certificate had a different issuer id from the subject id, or had it's own AuthorityKeyExtension the PKCS12 key store would drop the root certificate from the certificate chain. This has been fixed.
- The PKCS10 CertificationRequestInfo class always expected at least one attribute. This has been fixed.
- UTF-8 strings are now correctly recognised.
- The Tiger implementation was producing results in reverse byte order for each of the 3 words making up the digest. This has been fixed.
- asn1.x509.ExtendedKeyUsage used to throw a null pointer exception on construction. This has been fixed.

### 2.78.3 Additional Functionality and Features

- The BigInteger library now uses Montgomery numbers for modPow and is substantially faster.
- SMIMECapabilities, and SMIMEEncryptionKeyPreference attributes added to S/MIME.
- Increased range of key sizes available in S/MIME.
- getInstance(ASN1TaggedObject, boolean) methods have been added to most ASN1 types. These deal with implicit/explicit tagging ambiguities with constructed types.
- Added EncryptedPrivateKeyInfo object to the clean room JCE.
- A PEMReader has been added for handling some of the openSSL PEM files.
- The X.509 certificate factory supports a wider range of encodings and object identifiers.

<a id="r1rv13"></a>

### 2.79.1 Version

Release: 1.13\
Date: 2002, April 19

### 2.79.2 Defects Fixed

- The TBSCertificate object in the ASN.1 library now properly implements the Time object, rather returning UTC time.
- The DESedeKeyGenerator now supports 112 and 168 bit key generation.
- Certificates with the keyId set to null in the AuthorityKeyIdentifier extensions would sometimes cause the PKCS12 store to throw a NullPointer exception. This has been fixed.
- toByteArray in the big integer class was not always producing correct results for negative numbers. This has been Fixed.

### 2.79.3 Additional Functionality and Features

- The key to keySpec handling of the secret key factories has been improved.
- There is now a SMIME implementation and a more complete CMS implementation (see CONTRIBUTORS.md for additional details).
- A CertPath implementation that runs under jdk1.1 and jdk1.4 has also being contributed. A work around to allow it to be used with jdk1.2 and jdk1.3 has also been added. Note: the implementation is not quite complete because policymapping, name and subtree constraints are not yet implemented.
- The API now supports the generation of PKCS7 signed objects. Note: this is still beta code - one known issue is that it doesn't support single length certificate chains for signing keys.

<a id="r1rv12"></a>

### 2.80.1 Version

Release: 1.12\
Date: 2002, February 8

### 2.80.2 Defects Fixed

- The ASN.1 library was unable to read an empty set object. This has been fixed.
- Returning sets of critical and non-critical extensions on X.509 certificates could result in a null pointer exception if the certificate had no extensions. This has been fixed.
- The BC JKS implementation does not follow the conventional one - it has been renamed BKS, an attempt to create a JKS keystore using the BC provider will now result in an exception.
- The PKCS 10 generator verify(provider) method was ignoring the provider when generating the public key. This has been fixed.
- The PKCS12 store would throw an OutOfMemoryException if passed a non-PKCS12 file. This has been fixed.
- In the case where there was no AuthorityKeyIdentifier the PKCS12 store would fail to find certificates further up the signing chain. The store now uses the IssuerDN if no AuthorityKeyIdentifier is specified and the IssuerDN is different from the SubjectDN,
- PKCS10/CertificationRequestInfo objects with only a single attribute wer not being handled properly. This has been fixed.
- getExtensionValue for X.509 CRLs was returning the value of the DER-Encoded octet string not the DER-Encoded octet string as required. This has been fixed.
- the IV algorithm parameters class would improperly throw an exception on initialisation. This has been fixed.

### 2.80.3 Additional Functionality and Features

- The AESWrap ciphers will now take IV's.
- The DES-EDEWrap algorithm described in https://www.ietf.org/internet-drafts/draft-ietf-smime-key-wrap-01.txt is now supported.
- Support for the ExtendedKeyUsageExtension and the KeyPurposeId has been added.
- The OID based alias for DSA has been added to the JCE provider.
- BC key stores now implement the BCKeyStore interface so you can provide your own source of randomness to a key store.
- The ASN.1 library now supports GeneralizedTime.
- HMACSHA256, HMACSHA384, and HMACSHA512 are now added.
- PSS has been added to the JCE, PSS and ISO9796 signers in the lightweight api have been rewritten so they can be used incrementally. SHA256withRSA, SHA384withRSA, and SHA512withRSA have been added.
- Base support for CMS (RFC 2630) is now provided (see CONTRIBUTORS.md for details).

<a id="r1rv11"></a>

### 2.81.1 Version

Release: 1.11\
Date: 2001, December 10

### 2.81.2 Defects Fixed

- X9.23 padding of MACs now works correctly with block size aligned data.
- Loading a corrupted "UBER" key store would occasionally cause the appearance of hanging. This has been fixed.
- Loading a PKCS12 store where not all certificates had PKCS9 attributes assigned to them would cause a NullPointerException. This has been fixed.
- The PKCS12 store wasn't correctly recovering certificate chains of length less than 2 on calling the getCertificateChain method. This has been fixed.
- Lone certificates were not been stored in the PKCS12 store. This has been fixed.
- CFB and OFB modes weren't padding iv's more than 1 byte less than the block size of the cipher if the mode was reused with a shorter IV. This has been fixed.
- IV handling and block size return values for CFB and OFB modes wasn't being handled in the same way as the Sun reference implementation. This has been fixed.
- CertificateInfoRequests were not handling null attributes correctly. This has been fixed.
- Tags for the X.509 GeneralName structure were wrongly encoded. This has been fixed.
- getExtensionValue for X.509 certificates was returning the value of the DER-Encoded octet string not the DER-Encoded octet string as required. This has been fixed.
- reset on the version 3 X.509 certificate generator was not flushing the extensions. This has been fixed.
- The NetscapeCert type bits were reversed! This has been fixed.

### 2.81.3 Additional Functionality and Features

- The lightweight API and the JCE provider now support ElGamal.
- X509Principal, and X509Name now supports the "DC" attribute and the creation of directory names from vectors.
- RSA-PSS signature padding has been added to the lightweight API.
- EC Public/Private keys are now encoded in accordance with SEC 1. The library will still read older keys as well.
- Added PKCS12-DEF a pkcs12 based key store which works around a bug in the Sun keytool - it always uses the default provider for creating certificates.
- A cut down version of the Rijndael has been added that provides the functionality required to conform the the AES. It is designed to fully support FIPS-197. A fips AES wrapper (AESWrap in the JCE, AESWrapEngine in the lightweight library has also been added).
- Elliptic curve routines now handle uncompressed points as well as the compressed ones.

### 2.81.4 Other changes

- As the range of public key types supported has expanded the getPublicKey method on the SubjectPublicKeyInfo class is not always going to work. The more generic method getPublicKeyData has been added and getPublicKey now throws an IOException if there is a problem.

<a id="r1rv10"></a>

### 2.82.1 Version

Release: 1.10\
Date: 2001, October 20

### 2.82.2 Defects Fixed

- The PKCS12 Key Store now interoperates with the JDK key tool. **Note:** this does mean the the key name passed to the setKeyEntry calls has become significant.
- The "int" constructor for DERInteger only supported ints up to 128. This has been fixed.
- The ASN.1 input streams now handle zero-tagged zero length objects correctly.

### 2.82.3 Additional Functionality and Features

- The JCE Provider and the lightweight API now support Serpent, CAST5, and CAST6.
- The JCE provider and the lightweight API now has an implementation of ECIES. **Note:** this is based on a draft, don't use it for anything that needs to be kept long term as it may be adjusted.
- Further work has been done on performance - mainly in the symmetric ciphers.
- Support for the generation of PKCS10 certification requests has been added.

<a id="r1rv09"></a>

### 2.83.1 Version

Release: 1.09\
Date: 2001, October 6

### 2.83.2 Defects Fixed

- failure to pass in an RC5 parameters object now results in an exception at the upper level of the JCE, rather than falling over in the lightweight library.
- ISO10126Padding now incorporates the correct amount of random data.
- The PKCS12 key store wasn't picking up certificate chains properly when being used to write PKCS12 files. This has been fixed.
- The Twofish engine would call System.exit if the key was too large. This has been fixed.
- In some cases the ASN.1 library wouldn't handle implicit tagging properly. This has been fixed.

### 2.83.3 Additional Functionality and Features

- Support for RC5-64 has been added to the JCE.
- ISO9796-2 signatures have been added to the JCE and lightweight API.
- A more general paddings packge for use with MACs and block ciphers had been aded to the lightweight API. MACs now allow you to specify padding.
- X9.23 Padding has been added to the JCE and lightwieght API. The old PaddedBlockCipher class is now deprecated see org.bouncycastle.crypto.paddings for details.
- SHA-256, SHA-384, and SHA-512 are now added. Note: while the public review period has finished, these algorithms have not yet been standardised, in the event that final standardisation changes the algorithms these implementations will be changed.
- It's now possible to set bag attributes on items to go into a PKCS12 store, using the org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier interface.
- More classses have been added to the ASN.1 package for dealing with certificate extensions and CRLs including a CRL generator. Note: the CRL generators should be regarded as under development and subject to change.
- There's now an examples package for the JCE (in addition to the examples in org.bouncycastle.jce.provider.test) - org.bouncycastle.jce.examples. It currently consists of a class showing how to generate a PKCS12 file.
- The X.509 CertificateFactory now includes CRL support. DER or PEM CRLs may be processed.
- The BigInteger library has been written with a view to making it less resource hungry and faster - whether it's fast enough remains to be seen!

<a id="r1rv08"></a>

### 2.84.1 Version

Release: 1.08\
Date: 2001, September 9

### 2.84.2 Defects Fixed

- It wasn't possible to specify an ordering for distinguished names in X509 certificates. This is now supported.
- In some circumstances stream Ciphers in the JCE would cause null pointer exceptions on doFinal. This has been fixed.
- Unpadded ciphers would sometimes buffer the last block of input, even if it could be processed. This has been fixed.
- The netscape certificate request class wouldn't compile under JDK 1.1. This has been fixed.

### 2.84.3 Additional Functionality and Features

- ISO 9796-1 padding is now supported with RSA in the lightweight API and the JCE.
- support classes have been added for reading and writing PKCS 12 files, including a keystore for the JCA.
- The message digests MD4, Tiger, and RIPEMD128 have been added to the JCE and the lightweight API. Note: MD4 and RIPEMD128 have been added for compatibility purposes only - we recommend you don't use them for anything new!
- The JDK 1.1 certificate classes didn't conform to the JDK 1.2 API as the collections class was not present. Thanks to a donated collections API this is fixed.

<a id="r1rv07"></a>

### 2.85.1 Version

Release: 1.07\
Date: 2001, July 9

### 2.85.2 Defects Fixed

- It turned out that the setOddParity method in the DESParameter class was indeed doing something odd but not what was intended. This is now fixed. **Note:**This will affect some PBE encryptions that were carried out with DES, equivalent PBE ciphers to the old PBE DES cipher can be accessed by prepending the work "Broken" in front of the original PBE cipher call. If you want an example of how to deal with this as a migration issue have a look in org.bouncycastle.jce.provider.JDKKeyStore lines 201-291.

<a id="r1rv06"></a>

### 2.86.1 Version

Release: 1.06\
Date: 2001, July 2

### 2.86.2 Defects Fixed

- Diffie-Hellman keys are now properly serialisable as well as encodable.
- Three of the semi-weak keys in the DESParameters, and the DESKeySpec look up table, were incorrect. This has been fixed.
- DESEDE key generators now accept 112 and 168 as the key sizes, as well as 128 and 192 (for those people who don't like to count the parity bits).
- Providing no strength parameter is passed to the DESede key generator in the JCE provider, the provider now generates DESede keys in the k1-k2-k1 format (which is compatible with the Sun reference implementation), otherwise you get what you ask for (3-DES or 2-DES in the minimum number of bytes).
- Base Diffie-Hellman key agreement now works correctly for more than two parties.
- Cipher.getAlgorithmParameters was returing null in cases where a cipher object had generated it's own IV. This has been fixed.
- An error in the key store occasionally caused checks of entry types to result in a null pointer exception. This has been fixed.
- RSA key generator in JCE now recognises RSAKeyGenerationParameterSpec.
- Resetting and resusing HMacs in the lightweight and heavyweight libraries caused a NullPointer exception. This has been fixed.

### 2.86.3 Additional Functionality

- ISO10126Padding is now recognised explicitly for block ciphers as well.
- The Blowfish implementation is now somewhat faster.

<a id="r1rv05"></a>

### 2.87.1 Version

Release: 1.05\
Date: 2001, April 17

### 2.87.2 Defects Fixed

- The DESEDE key generator can now be used to generate 2-Key-DESEDE keys as well as 3-Key-DESEDE keys.
- One of the weak keys in the DESParameters, and the DESKeySpec look up table, was incorrect. This has been fixed.
- The PKCS12 generator was only generating the first 128-160 bits of the key correctly (depending on the digest used). This has been fixed.
- The ASN.1 library was skipping explicitly tagged objects of zero length. This has been fixed.

### 2.87.3 Additional Functionality

- There is now an org.bouncycastle.jce.netscape package which has a class in for dealing with Netscape Certificate Request objects.

### 2.87.4 Additional Notes

Concerning the PKCS12 fix: in a few cases this may cause some backward compatibility issues - if this happens to you, drop us a line at <feedback-crypto@bouncycastle.org> and we will help you get it sorted out.

<a id="r1rv04"></a>

### 2.88.1 Version

Release: 1.04\
Date: 2001, March 11

### 2.88.2 Defects Fixed

- Signatures generated by other providers that include optional null parameters in the AlgorithmIdentifier are now handled correctly by the provider.
- The JCE 1.2.1 states that the names of algorithms associated with the JCE are case insensitive. The class that matches algorithms to names now tries to match the name given with it's equivalent in upper case, before trying to match it as given. If you write a provider and include versions of your algorithm names in uppercase only, this JCE implementation will always match a getInstance regardless of the case of the algorithm passed into the getInstance method.
- If the JCE API and the Provider were in a different class path, the class loader being used sometimes failed to find classes for JCE Ciphers, etc. This has been fixed.
- An error in the ASN.1 library was causing problems serialising Diffie-Hellman keys. This has been fixed.
- The agreement package was left out of the j2me bat file. This has been fixed.
- The BigInteger class for 1.0 and the j2me wasn't able to generate random integers (prime or otherwise). This has been fixed.
- The BigInteger class would sometimes go into a death spiral if the any 32nd bit of an exponent was set when modPow was called. This has been fixed.
- Cipher.getInstance would treat "//" in a transformation as a single "/". This has been fixed.
- PBEWithSHAAndIDEA-CBC was throwing an exception on initialisation. This has been fixed.
- The X509Name class in the asn1.x509 package wasn't initialising its local hash table when the hash table constructor was called. This has been fixed.

### 2.88.3 Additional Functionality

- Added Elliptic Curve DSA (X9.62) - ECDSA - to provider and lightweight library.
- Added Elliptic Curve basic Diffie-Hellman to provider and lightweight library.
- Added DSA support to the provider and the lightweight library.
- Added super class interfaces for basic Diffie-Hellman agreement classes to lightweight library.
- The certificate generators now support ECDSA and DSA certs as well.

<a id="r1rv03"></a>

### 2.89.1 Version

Release: 1.03\
Date: 2001, January 7

### 2.89.2 Defects Fixed

- CFB and OFB modes when specified without padding would insist on input being block aligned. When specified without padding CFB and OFB now behave in a compatible fashion (a doFinal on a partial block will yield just the data that could be processed). In short, it provides another way of generating cipher text the same length as the plain text.

<a id="r1rv02"></a>

### 2.90.1 Version

Release: 1.02\
Date: 2000, November 7

### 2.90.2 Defects Fixed

- The RSA key pair generator occasionally produced keys 1 bit under the requested size. This is now fixed.

<a id="r1rv01"></a>

### 2.91.1 Version

Release: 1.01\
Date: 2000, October 15

### 2.91.2 Defects Fixed

- Buffered ciphers in lightweight library were not resetting correctly on a doFinal. This has been fixed.

<a id="r1rv00"></a>

### 2.92.1 Version

Release: 1.00\
Date: 2000, October 13

### 2.92.2 Defects Fixed

- JDK1.2 version now works with keytool for certificate generation.
- Certificate toString method no longer throws a null pointer exception if a group [3] extension has not been added.
- Under some circumstances the NullCipher would throw a NullPointerException, this has been fixed.
- Under some circumstances CipherInputStream would throw a NullPointerException, this has been fixed.
- OpenSSL/SSLeay private key encodings would cause an exception to be thrown by the RSA key factory. This is now fixed.
- The Cipher class always used the default provider even when one was specified, this has been fixed.
- Some DES PBE algorithms did not set the parity correctly in generated keys, this has been fixed.

### 2.92.3 Additional functionality

- Argument validation is much improved.
- An X509KeyUsage class has been added to the JCE class to make it easier to specify the KeyUsage extension on X.509 certificates.
- The library now allows creation of version 1 certificates as well.

### 3.0 Notes

The J2ME is only supported under Windows.

If you are trying to use the lightweight provider in a JDK 1.0 applet, you need to change the package names for java.math.BigInteger, java.lang.IllegalStateException, and java.security.SecureRandom

The RSA test under JDK 1.0 and J2ME takes a while to run...
