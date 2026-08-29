# XMSS private key encoding

This document describes the byte encodings Bouncy Castle uses for an XMSS (RFC 8391) private
key: the raw form produced by
`org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.getEncoded()`, the versioned binary
BDS traversal state embedded in it, and the two PKCS#8 wrappings.

RFC 8391 deliberately does not define a private-key format: *"we do not define any specific
format or handling for the XMSS private key SK"* (sec. 4.1.7, and equivalently sec. 4.2.2 for
XMSS^MT). RFC 9802 assigns the `id-alg-xmss-hashsig` algorithm identifier used in the PKCS#8
wrapping but is a certificate/public-key profile and does not define the private-key octets
either. Everything below is therefore a Bouncy Castle implementation format, stable across BC
releases but not an interchange format defined by any standard.

XMSS is stateful: the private key advances with every signature, and the caller must persist
the updated key each time. All of the encodings below capture a key *at a particular index*,
and their length is not constant — the traversal state grows and shrinks as the tree walk
proceeds (the example key below is 1138 raw bytes at index 0 and 1182 at index 1).

## Raw key: `XMSSPrivateKeyParameters.getEncoded()`

With `n` the tree-digest size in bytes (32 for the SHA-256 parameter sets), all integers
unsigned big-endian:

| offset | size | field | contents |
|---|---|---|---|
| 0 | 4 | `index` | Index of the next unused WOTS+ leaf; `0` for a fresh key. |
| 4 | `n` | `secretKeySeed` | `SK_1`: the seed the per-leaf WOTS+ private keys are derived from. |
| 4 + `n` | `n` | `secretKeyPRF` | `SK_2`: the PRF key used to derive per-message randomness. |
| 4 + 2`n` | `n` | `publicSeed` | `SEED`, as in the public key. |
| 4 + 3`n` | `n` | `root` | The tree root, as in the public key. |
| 4 + 4`n` | rest | `bdsState` | The binary BDS traversal state described below. |

## The binary BDS state

The BDS state is the working state of the tree-traversal algorithm ([BDS09], referenced from
RFC 8391 sec. 4.1.9) that lets each signature compute its authentication path without
regenerating the tree. Since release 1.86 it is written in a versioned binary form
(`org.bouncycastle.pqc.crypto.xmss.BDSStateCodec`); earlier releases wrote a Java
`ObjectOutputStream` stream here instead, which 1.86+ still *reads* (through a restricted
class allow-list) but never generates. The conversion is one way: once a key has been
re-persisted by 1.86 or later, releases before it fail to read the state.

All integers unsigned big-endian; `bool` is one byte, `00` or `01`, anything else rejected. A
*node* is encoded as `height u32 || valueLen u32 || value`, where `valueLen` is `n` (all nodes
in one state must agree). An *optional node* is a `bool` presence flag followed, when `01`, by
a node.

```
u32   magic              0x42445300 ("BDS\0")
u32   version            1
u32   treeHeight         h (2..30)
u32   k                  the BDS time/memory trade-off parameter (BC uses 2);
                         2 <= k <= treeHeight, treeHeight - k even
u32   maxIndex           highest usable leaf index (2^h - 1 for a full key;
                         less for a shard from extractKeyShard())
u32   index              current leaf index (0 .. maxIndex + 1)
bool  used
opt   root               node of height treeHeight
u32   authPathCount      0, or exactly treeHeight
node  authPath[0..c-1]   node i has height i
u32   retainCount        at most k - 1 entries, heights strictly increasing
        u32  height          treeHeight - k .. treeHeight - 2
        u32  nodeCount
        node nodes[]
u32   stackCount         at most treeHeight
node  stack[]            pushed in encoded order; heights 0 .. treeHeight
u32   treeHashCount      exactly treeHeight - k
        u32  initialHeight   equal to the entry's position
        u32  height          0 .. initialHeight
        u32  nextIndex
        bool initialized
        bool finished
        opt  tailNode        height at most initialHeight
u32   keepCount          at most treeHeight entries, heights strictly increasing
        u32  height          0 .. treeHeight - 2
        node node
byte  checksum[32]       SHA-256 over the owning key's publicSeed followed by every byte
                         of this state above; see below
```

Decoding is defensive: the trailing checksum is verified before anything else is parsed, the
whole state is capped at 4 MiB, the total node count at 4096, node values at 64 bytes, every
count is validated against the bounds above before allocation, and trailing data after the
`keep` map is rejected. After decoding, the state is cross-checked against the key's XMSS
parameters (heights, `k`, digest size), its `index` against the enclosing key's, and its
`root` against the enclosing key's `root` field, before the key can be used.

The checksum exists because a BDS node value cannot be verified any other way: an
authentication path, stack, retain or keep node does not have its children stored beside it, so
recomputing one means rebuilding a subtree — the work this state exists to avoid. The owning
key's `publicSeed` is hashed in front of the state so that a state transplanted between two
keys of the same parameter set fails the check even though it is internally consistent. **It is
an error-detecting code, not integrity protection**: anyone able to rewrite the stored key
recomputes it, so it establishes only that the state is unchanged since it was written, never
that it was correct when written — which is why the allocation bounds above still matter. Note
it is SHA-256 whatever the parameter set's tree digest is; this is a checksum over a BC
encoding, not part of any scheme.

An XMSS^MT private key stores a map of BDS states, one per populated layer, under its own
header: magic `0x42444d00` ("BDM\0"), `u32` version 1, `u64` maxIndex, `u32` state count, then
per entry a `u32` layer number (strictly increasing) followed by a BDS record as above.

## PKCS#8 wrapping

There are two forms, chosen by whether the parameter set is one of the standard RFC 8391 /
NIST SP 800-208 sets:

**Standard parameter sets** (the normal case) use the RFC 9802 algorithm identifier
`id-alg-xmss-hashsig` (1.3.6.1.5.5.7.6.34) with absent parameters — the same OID the public
key uses. The `privateKey` OCTET STRING contains a nested OCTET STRING holding the 4-octet
numeric parameter-set identifier from the IANA "XMSS Signatures" registry (values defined in
RFC 8391 sec. 5.3 and NIST SP 800-208, e.g. `0x00000001` = XMSS-SHA2_10_256), followed by the
raw key above. The parameter-set identifier
is carried because the raw key does not otherwise name its own parameters.

**Non-standard tree heights** have no parameter-set identifier and fall back to the legacy BC
OID 1.3.6.1.4.1.22554.2.2 with `XMSSKeyParams` (height + tree-digest AlgorithmIdentifier) as
the algorithm parameters, and the ASN.1 structure `org.bouncycastle.pqc.asn1.XMSSPrivateKey`
as the key body:

```
XMSSPrivateKey ::= SEQUENCE {
    version INTEGER,                 -- 0, or 1 when maxIndex is present
    keyData SEQUENCE {
        index         INTEGER,
        secretKeySeed OCTET STRING,
        secretKeyPRF  OCTET STRING,
        publicSeed    OCTET STRING,
        root          OCTET STRING,
        maxIndex      [0] INTEGER OPTIONAL
    },
    bdsState CHOICE {
        legacyBdsState [0] OCTET STRING,   -- Java serialization; read but never written
        binaryBdsState [1] OCTET STRING    -- the binary BDS state above
    } OPTIONAL
}
```

## Worked example

Generated with `XMSSKeyPairGenerator` for XMSS-SHA2_10_256 (`h = 10`, SHA-256), using fixed,
obviously non-secret seed material so the example is reproducible: the generator draws
`secretKeySeed`, `secretKeyPRF` and `publicSeed` from its `SecureRandom`, here supplied as the
byte sequences `000102...1f`, `202122...3f` and `404142...5f`. **This is a published example —
never use this key.**

The complete fresh PKCS#8 encoding is 1169 bytes (the raw key is 1138: the 132-byte fixed
portion plus a 1006-byte BDS state):

```
3082048d020100300a06082b060105050706220482047a0482047600000001000000000001020304
05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c
2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354
55565758595a5b5c5d5e5f85055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1
ba9cc442445300000000010000000a00000002000003ff0000000000010000000a0000002085055d
10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc40000000a00000000000000
202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e37bb916300000001000000
20e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f500000002000000
20d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e800000003000000
2068538e5a1e958ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000004000000
207fa6b5eb231fdba25172edd2c7ca5b62ab47896d6db77d61e3245687b3447d5400000005000000
20589185e48d2d09b9d00eef5b3120c61c4ae5d80b2db67cdcfeef163942c5fdb400000006000000
20ec2abf80b41083e3c66db3a9569b466a66dd21f9ff225bd77c43b7e6e9ece4df00000007000000
20c85b31510868d3f7c03dc4024d164ca74386edb59708b2d1d6bc418bde44045800000008000000
20560566ee6f35497c224298b16740c4158d5d369e80d3aaa6e75969207cbed00500000009000000
209d8828eb13493fa98d516a1b87b9528b31a63975268760a59543cb4bae3403bc00000001000000
080000000100000008000000205512ffdc18cc64a201e3d5a189bbe38f2793d9a835b73421ab3bcd
00d7aa7349000000000000000800000000000000000000000000010100000000000000201c004781
827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000010000000100000000
00010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8
efa4e4000000020000000200000000000101000000020000002097988034c44f4964156ce4fc7ddb
604978835d40bf019ee0097f961323d5254d00000003000000030000000000010100000003000000
20ff7c4238f040c81306f3fe7e84fe7201bab69d5e1f721a7dd86d858feae300a900000004000000
0400000000000101000000040000002055aeb24e79e15b2fd7e4d14fc6ee4138ce908b74a573825e
7c20c14ed8671f67000000050000000500000000000101000000050000002093483dacc20a2707a9
2d47780643bd1c908925e4f7104ea1f6195f0d1a3a465f0000000600000006000000000001010000
0006000000201b20cd7e03af01c8c3c02541b0a987021031e3c5104c5077fd3bc8f4a097462d0000
000700000007000000000001010000000700000020f0be26c249b7362ec7b7445c2740c32610f97b
ff061f424a7e55168fe8ce5b5000000000c81fa7f8cd65e71c31cc33e6ef65708f1648986d7b6d04
ce8d700db77e493173
```

The outer layers:

```
3082048d                            SEQUENCE, 1165 bytes (PrivateKeyInfo)
  020100                            INTEGER 0 (v1 - no public key attached)
  300a06082b06010505070622          AlgorithmIdentifier 1.3.6.1.5.5.7.6.34, absent parameters
  0482047a 04820476                 OCTET STRING within OCTET STRING, 1142 bytes:
    00000001                        parameter set XMSS-SHA2_10_256
    <1138 bytes>                    the raw key
```

The raw key:

```
00000000                            index      0 (fresh key, no signatures yet)
000102...1f                         secretKeySeed (32 bytes)
202122...3f                         secretKeyPRF  (32 bytes)
404142...5f                         publicSeed    (32 bytes)
85055d10d75c7d9f50d5d90dd43827a9
0fbcf397b76d3877ba85bfbde1ba9cc4    root
<1006 bytes>                        binary BDS state
```

And the head of the BDS state, offset 132 of the raw key:

```
42445300                            magic "BDS\0"
00000001                            version 1
0000000a                            treeHeight 10
00000002                            k 2
000003ff                            maxIndex 1023
00000000                            index 0
00                                  used = false
01 0000000a 00000020 85055d10...    root present, height 10, 32 bytes (= the root above)
0000000a                            authentication path: 10 nodes
00000000 00000020 2caf15d3...       authPath[0]: height 0, 32 bytes
...                                 authPath[1..9]
```

The remainder of this particular state holds one retained node at height 8, an empty stack,
eight treeHash instances (heights 0..7, each finished with a tail node), and an empty keep
map, and the trailing checksum — 1006 bytes in all, in the layout given above. After one
signature the raw key differs first at byte offset 3 (`index` becomes 1) and re-encodes at
1182 bytes, the state having grown by the nodes the traversal now keeps in flight.

The corresponding RFC 9802-style public key body (`parameter set || root || publicSeed`):

```
0000000185055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc440414243
4445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
```

## Where this is implemented

- `core/src/main/java/org/bouncycastle/pqc/crypto/xmss/XMSSPrivateKeyParameters.java` — the
  raw form (`getEncoded()`, and the `Builder` that reads it back).
- `core/src/main/java/org/bouncycastle/pqc/crypto/xmss/BDSStateCodec.java` — the binary BDS
  state codec (and the XMSS^MT state-map variant).
- `core/src/main/java/org/bouncycastle/pqc/crypto/util/PrivateKeyInfoFactory.java` /
  `PrivateKeyFactory.java` — both PKCS#8 wrappings.
- `core/src/main/java/org/bouncycastle/pqc/asn1/XMSSPrivateKey.java` — the legacy ASN.1
  structure used for non-standard tree heights.
