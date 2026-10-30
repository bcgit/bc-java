/**
 * Crypto-services-constraint framework: lets callers limit which cryptographic
 * primitives the lightweight API will produce (by key size, by allowlist, by purpose, or - for
 * the quantum-vulnerable public-key algorithms - by the NIST IR 8547 transition timetable).
 * Plugs into {@link org.bouncycastle.crypto.CryptoServicesRegistrar}. The post-quantum
 * algorithms report to the framework with the classical security strength NIST assigns to
 * their parameter set, so a {@link org.bouncycastle.crypto.constraints.BitsOfSecurityConstraint}
 * of 192 refuses ML-KEM-512, ML-DSA-44 and the 128-bit SLH-DSA sets as it does a 2048-bit RSA key.
 * {@link org.bouncycastle.crypto.constraints.QuantumVulnerableConstraint} can also log, or refuse
 * outright, the quantum-vulnerable algorithms, and the
 * {@link org.bouncycastle.util.Properties#CONSTRAINTS_QUANTUM_VULNERABLE} property installs one as
 * the default constraint. The framework is described in section 5.8 of the specifications document.
 */
package org.bouncycastle.crypto.constraints;
