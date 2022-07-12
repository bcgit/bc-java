/**
 * The NTRU algorithm based on the round 3 submission of the NIST post-quantum cryptography. For the old NTRU, see
 * {@link org.bouncycastle.pqc.legacy.crypto.ntru}.
 *
 * <p>
 * This implementation is based on the C reference implementation submitted for the round 3 NIST PQC competition,
 * released under CC0-1.0 license.
 * </p>
 *
 * <p><a href="https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/NTRU-Round3.zip">NIST submission files</a></p>
 * <p><a href="https://github.com/jschanck/ntru/blob/master/LICENSE">License of reference implementation</a></p>
 *
 * @see <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">NIST round 3 PQC submissions page</a>
 * @see <a href="https://ntru.org/">NTRU website</a>
 * @see <a href="https://ntru.org/f/ntru-20190330.pdf">NTRU specification</a>
 */
package org.bouncycastle.pqc.crypto.ntru;