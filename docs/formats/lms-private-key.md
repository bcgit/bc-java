# LMS private key encoding

This document describes the byte encoding Bouncy Castle uses for a Leighton-Micali Signature
(LMS) private key — the value returned by
`org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters.getEncoded()` and accepted by
`LMSPrivateKeyParameters.getInstance()`, and the payload carried inside a PKCS#8
`PrivateKeyInfo` for an LMS key.

RFC 8554 deliberately does not define this: *"The format of the LMS private key is an internal
matter to the implementation, and this document does not attempt to define it."* (RFC 8554
sec. 5.2). The encoding below is therefore a Bouncy Castle implementation format, stable across
releases for interoperability between BC versions, but not an interchange format defined by any
standard. The public key and signature formats, by contrast, are RFC 8554 wire formats and are
not described here.

## Layout

All multi-byte integers are unsigned 32-bit, big-endian (`u32`). There is no framing; fields
are concatenated in order.

| offset | size | field | contents |
|---|---|---|---|
| 0 | 4 | `version` | `0`. The only version defined; anything else is rejected. |
| 4 | 4 | `type` | LMS parameter-set typecode, per the "Leighton-Micali Signatures (LMS)" IANA registry of RFC 8554 sec. 8 (e.g. `0x05` = LMS_SHA256_M32_H5). Resolved via `LMSigParameters`; an unknown code is rejected with an `IOException`. |
| 8 | 4 | `otstype` | LM-OTS parameter-set typecode, per the "LM-OTS Signatures" IANA registry of RFC 8554 sec. 8 (e.g. `0x03` = LMOTS_SHA256_N32_W4). Resolved via `LMOtsParameters`; an unknown code is rejected with an `IOException`. |
| 12 | 16 | `I` | The key-pair identifier, exactly 16 bytes (RFC 8554 sec. 5.3). The same `I` appears in the public key and in every signature's OTS component. |
| 28 | 4 | `q` | Index of the next unused OTS leaf. `0` for a fresh key; incremented by each signature. LMS is stateful: this field is why an updated private key must be re-persisted after signing. |
| 32 | 4 | `maxQ` | Exclusive upper bound on `q`. `2`<sup>`h`</sup> for a freshly generated key; a key shard produced by `extractKeyShard()` carries the sub-range it may use, so `q` and `maxQ` describe the shard's remaining allocation. The key is exhausted when `q == maxQ`. |
| 36 | 4 | `secretLen` | Length in bytes of the master secret that follows: `m` for the parameter set in use (32 for the n32 sets, 24 for the n24 sets). Checked against the remaining input before allocation. |
| 40 | `secretLen` | `masterSecret` | The seed all per-leaf LM-OTS private keys are derived from deterministically. This is the only secret material in the encoding. |
| 40 + `secretLen` | 4 | `cacheCount` | *Optional trailer.* Number of cached top-of-tree nodes that follow (`n`, in the range 0..63). May be absent entirely — the encoding simply ends after `masterSecret` — which is how every release before 1.86 wrote the key. |
| 44 + `secretLen` | `n` × `m` | `T[1] .. T[n]` | The top `n` nodes of the Merkle tree, `m` bytes each, in node-number order. Node numbering follows RFC 8554 sec. 5.3: `T[1]` is the root (the public key's node value), `T[r]` has children `T[2r]` and `T[2r+1]`. |

## The tree-cache trailer

The trailer was added in release 1.86 (github #2365) so that a freshly decoded key does not
have to rebuild the Merkle tree — which costs about as much as key generation — before its
first signature. Its properties:

- **It is optional in both directions.** `getInstance()` accepts an encoding that ends at the
  master secret (a key written by 1.85 or earlier, which then rebuilds the tree on first use),
  and a release predating the cache reads a 1.86+ encoding successfully because its decoder
  returns at the end of the master secret and never examines the trailing bytes. This is why
  the cache is appended rather than announced by a new version number.
- **It carries at most the top six levels** of the tree: nodes `1 .. min(2`<sup>`h+1`</sup>`, 64) - 1`.
  For `h = 5` that is the entire tree (63 nodes); for `h = 10` and above it is the top 63
  nodes, from which the remaining path nodes are recomputed on demand.
- **It discloses nothing the encoding does not already disclose**: every `T[r]` is a
  deterministic function of `I`, the master secret and the parameter set, all of which precede
  it, and is independent of `q`.
- **It is validated before allocation**: the count must be below 64 and the declared node data
  must not exceed the remaining input.

## PKCS#8 wrapping

`org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory` wraps an LMS private key as a
`OneAsymmetricKey` (RFC 5958, version `v2` since the public key is included) with algorithm
`id-alg-hss-lms-hashsig` (1.2.840.113549.1.9.16.3.17). Because that OID names the HSS scheme,
of which a single LMS tree is the one-level case, the octets are prefixed with the HSS level
count `L = 1`:

```
PrivateKeyInfo ::= SEQUENCE {
    version                Version,             -- v2(1), public key present
    privateKeyAlgorithm    AlgorithmIdentifier, -- 1.2.840.113549.1.9.16.3.17, absent parameters
    privateKey             OCTET STRING,        -- u32(1) || <the LMS encoding above>
    publicKey          [1] BIT STRING           -- u32(1) || <RFC 8554 LMS public key>
}
```

An HSS private key with `L > 1` uses the same OID and prefix convention but a different body
(the HSS key chain state); it is not covered here.

## Worked example

Generated with `LMSKeyPairGenerator` for LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W4, using fixed,
obviously non-secret seed material so the example is reproducible: the generator draws `I` and
then the master secret from its `SecureRandom`, here supplied as the byte sequences
`000102...0f` and `101112...2f`. **This is a published example — never use this key.**

The complete fresh encoding is 2092 bytes: the 72-byte fixed portion, the 4-byte cache count,
and 63 cached nodes of 32 bytes (`h = 5`, so the whole tree is cached).

Field breakdown:

```
00000000                            version    0
00000005                            type       LMS_SHA256_M32_H5
00000003                            otstype    LMOTS_SHA256_N32_W4
000102030405060708090a0b0c0d0e0f    I
00000000                            q          0 (fresh key, no signatures yet)
00000020                            maxQ       32 = 2^5
00000020                            secretLen  32
101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f    masterSecret
0000003f                            cacheCount 63
661aeb1d85e6a993e0e55bbbad2564f1
b45e3e1ba8b9b4c917e993ebbdaf19e2    T[1] - the tree root, as in the public key
5e4395871bd72c51372b5c81bbade31d
9238f93cee975967c99a20ce7d54e1c2    T[2]
...                                 T[3] .. T[63], 32 bytes each
```

The full encoding, as one hex string:

```
000000000000000500000003000102030405060708090a0b0c0d0e0f000000000000002000000020
101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f0000003f661aeb1d
85e6a993e0e55bbbad2564f1b45e3e1ba8b9b4c917e993ebbdaf19e25e4395871bd72c51372b5c81
bbade31d9238f93cee975967c99a20ce7d54e1c2450af91dee7210aa3247177281a7a063796eab48
cddfbbe47a16fa89a7a81a7c3cd651a8365fae5822f7493b63411d0ba98ba5c5953f35ea03d8f91c
e99a0dda5393429330662d5caf3f0ed9a96c4e9cd0ccf4d9f9251a51b2a060ba7ca433d288820ad0
7ec2e8926d4018399507852edc017c600f62e9e0985414c186fef4bb693694364269f5fd8e768fc0
0e7d2695c0db48716daf14fc151403783243b0e3b5720bb9286af384d66671d7cd91f3ddb17adbfe
66276cdb731ea36ec85002c325bffccd66e08ba479192e28b2d5b71fd66a836d67c1231053cfccc1
8700c8d145aad1742f4ec8a4d5f2aaf65268c9c3fb11a0f4f825805efc0ee44babcb15fb107a8ac0
0fce52cd668a4902dc106d9e5a28bf89e6c1f953b249802df3553d96d20f71d942b85813047e10dd
bb22b7e6ebd3c10777769becdbc74d4e8e0b8564f46f36e7b405ed16b50253c882de82666ed58d12
7880192831a111ac6210d841f107902627395d79eae8658c4244ea16e997e4df4a7a75f69423e924
4519c5406f4dcd9be1d280619ddeb3d788060d2723803ba1282f17ac87b7884d3a04146cc1208215
5db2b6f321f37797d171b644690fb4b7b00bbbff99aac7969d7bde4f3b15b2141a7c43c925375f48
38255645faabfa3dffd63511a3fe9e024b9bb26da07dbf3ba7568544b17e636c802631a4cca88657
0678275fe89f24d58f5ba0d1297a783fb3af4c706f4d4599f5b2e682e34c6303939d5395b10a51b2
b256558025ca3f172904214ce0544ad230e30acc13166298158044117fe93aa118af5b1e7a602bdb
eeb53c8614649f50ddb45d7461a2824de7026426d1406886103a4e9730a36a090afaa443805e6aa1
871e7c46e69b237ac924e48d7660b06f4b1ed2a98a2fc5baebe6928d9a7540284ad87cfc371864a1
b3f971004aa999e63a55f43ab0b57671a5f2bc4cb664238100c68a71dea9af23ed230a0b3e8d3ea5
3f7d113275526c6fffa5cc666e5a7f51bd0f0368737345fd91b68417e3a8825b0d12802c85ba6686
6cce983f755d780f3b4de637d50c856bbc0957145b4d412f130f01c8da530171ec5e21ff039485a1
a81c1fb81940d0f887846df8bc94f983af8074545227c243b289f6bc54b820cb2e8bdb2d85436679
10719ee781d2d2c492b4f824d9470520ad14120f7036be3979b900febf4b0c4599d73164cf6d1968
8bc6585141ba2c877fe9620857d2ffff4f2f664653e1ff33e87c220ab38e56c7aa08a67a38569fca
fe3d41b178891b7671153aa2f87e4fc5bdcf048a5db066848a75eb282c05d593882be7288dbeacff
8a642020ad3ef75e3072e466807cad2dd35f477b21e583dcd6ead0a36866cbdc42b69f18c9fc5ffe
29945c8e6c74c47069fc7c9113e8f2aa2e20dc0e6448c745d0023112367398ce0d4348cf6bf738a4
87d923e2af846f478e9e67a41f561934e5ac451d08768bb44f1547e2829d8e5ee94c6aea09bdd2c3
a30bd45ceb446dc052255f23383fdf3a6f16a91a270057020d84adcfb994f45e3352273adc097f51
0042d9dbefb04993be40b6ab9e0446289ded8dafcf0925f136aa97d9ea5afc8ab27bd8333bfe3fa7
b649f2457109059195716e8c00b7513bb56fa2489b84828786596331ff66495473dc15357b5a5bc2
dfe9f6f8ce47e9d55bd776e2a036e7488b15e9d94576760d24f8ea6ed9e5ee116371c08907734993
cb66e2a74bf4863f7e4585844eba4129aa6a1f08668a43c78474573682f8af99de4952a1e7eb4cb4
b48e6f2853050d69d5ce3afbdb865cb8cebe16babce73ba6e72144d526410ece5e12e4768be1c320
816cdfd26a8a8f9c1c6a0dfb3cfe10a04635ffab2bb3e8009e558566d1618896e72daeeed0c2128b
6e634b533a016076988ff2d0e7bcec6f435e12c43d15feff5877e5d5ea8d0dcb310f5da83ca1012d
5179c4cac7d4f282fae19df54698e11baad264d2b8f4b140787f37560aba9c8cf0a445971f033bb3
76a0915d249cb770833619ab4d567e436bbaf25c7794ac19148b18f3d1ce3688e14d2caf13cfbe23
e498f23ac066ffd1d09d1ec6ea492b7bab77ba16986b1b77852a4d2af1d23252d335c086c1b63e08
c6f2bdd52fe94887867a200b0b93001d650ac7fcbe82c733b91fccbd11cde6d553fd6ce5bbe5e7cd
a52f6a7b23dacd30610de3bcbf36ce666540eb1e3935ae1fb21bc8ea103740aeb4ed769fa8c2146f
a5af66dde0ae7e2a8ea323e62784f321565eb2f9771ed2d0a257eb179b56b5411bef8da8b04ebd02
6d8aafd4525b8cdf6a32c43657b91aac306a7582787ba48d7217f9be57429521e6d6c4569cf34240
7b4453535ad3224c8a453e9387047ccf92e01360997752b8dbe269d8c939c4f63ace5e4fea870214
e98753b828b6737108ae681d7960317f3f3d2dee1b88fddc6686923f1116aa9cbebe5f637b982ac6
af9f79f571f5e9a5f4e4935859153d0e9607b86ef968c8eb86657f1652ac29f538c3992311c18153
45970dd6417900c2e69131377ad2d5dd44f496a543c64252bf20efbbc974905384d889493fc887e1
94e100050f2ae98c097166d219ae62b8c85f732df9d763c2a70f8ce9dae13267d2204369e92c0e20
2a120d5d6c2202053c168a400f5ea02dd032cb4f05b59e465e939964fdd2812c56bebaec3097f683
128d80eced62ef915cd61cd355f98d4ce55e2c998fa963b17d6b12871b674efa52300adbf6262e4e
c7d022a36878e7c7776d6fa5
```

After one signature the encoding is byte-for-byte identical except that `q` at offset 28 reads
`00000001` — everything else, including the cache, is independent of the signature index.

The corresponding RFC 8554 public key (56 bytes: `type || otstype || I || T[1]`):

```
0000000500000003000102030405060708090a0b0c0d0e0f
661aeb1d85e6a993e0e55bbbad2564f1b45e3e1ba8b9b4c917e993ebbdaf19e2
```

Wrapped in PKCS#8, the same key (here after its first signature, `q = 1`) becomes a 2189-byte
`PrivateKeyInfo` whose `privateKey` OCTET STRING is `00000001` (the HSS `L = 1` prefix)
followed by the 2092 bytes above, and whose `publicKey` BIT STRING is `00000001` followed by
the 56-byte public key:

```
30820889                                    SEQUENCE, 2185 bytes
  020101                                    INTEGER 1 (v2 - public key present)
  300d060b2a864886f70d0109100311            AlgorithmIdentifier 1.2.840.113549.1.9.16.3.17
  0482083404820830 00000001 <2092 bytes>    OCTET STRING within OCTET STRING: L=1 || LMS key
  813d 00 00000001 <56 bytes>               [1] BIT STRING (0 unused bits): L=1 || public key
```

## Where this is implemented

- `core/src/main/java/org/bouncycastle/pqc/crypto/lms/LMSPrivateKeyParameters.java` —
  `getEncoded()` writes the format, `getInstance()` reads and validates it.
- `core/src/main/java/org/bouncycastle/pqc/crypto/util/PrivateKeyInfoFactory.java` /
  `PrivateKeyFactory.java` — the PKCS#8 wrapping and unwrapping.
