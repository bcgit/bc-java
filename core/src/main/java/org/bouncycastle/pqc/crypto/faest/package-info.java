/**
 * Lightweight implementation of FAEST &mdash; symmetric-primitive digital signature
 * scheme based on AES and the VOLE-in-the-Head proof system. Round 3 candidate of
 * <a href="https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures">
 * NIST&apos;s post-quantum additional signatures process</a>.
 *
 * <h2>References</h2>
 * <ul>
 *   <li>Specification: <a href="https://faest.info/faest-spec-v2.0.pdf">FAEST v2.0
 *       Algorithm Specifications</a>.</li>
 *   <li>Reference implementation:
 *       <a href="https://github.com/faest-sign/faest-ref">faest-sign/faest-ref</a>.</li>
 * </ul>
 *
 * <h2>Parameter sets</h2>
 * Twelve parameter sets per the v2.0 spec, identified by BC-arc OIDs declared in
 * {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers}:
 * <ul>
 *   <li>Base FAEST (AES one-way function):
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_128s faest_128s},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_128f faest_128f},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_192s faest_192s},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_192f faest_192f},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_256s faest_256s},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_256f faest_256f}.</li>
 *   <li>FAEST-EM (Even-Mansour one-way function):
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_em_128s faest_em_128s},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_em_128f faest_em_128f},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_em_192s faest_em_192s},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_em_192f faest_em_192f},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_em_256s faest_em_256s},
 *       {@link org.bouncycastle.asn1.bc.BCObjectIdentifiers#faest_em_256f faest_em_256f}.</li>
 * </ul>
 * The {@code s} (small) variants minimise signature size at the cost of slower
 * signing/verification; the {@code f} (fast) variants invert the trade-off.
 *
 * <h2>Side-channel posture</h2>
 * All FAEST-specific arithmetic (GF(2^&lambda;) and GF(2^8) field ops, byte-combine
 * helpers, constraint primitives, witness expansion, key schedule, top-level
 * prover/verifier) is strictly constant-time: it uses mask-based bit selection and
 * has no secret-indexed table lookups. The AES used internally for the OWF and
 * Even-Mansour round-key derivation runs through {@link FaestAES}, whose S-box is
 * computed via the bit-serial {@link BF8#inv} squaring chain rather than a lookup
 * table. The PRG used to expand the BAVC seed tree calls
 * {@link org.bouncycastle.crypto.engines.AESEngine} for performance reasons; that
 * engine clones its S-box on every {@code init()} call, which BC documents as
 * sufficient to defeat cache-line monitoring of the secret seed material.
 */
package org.bouncycastle.pqc.crypto.faest;
