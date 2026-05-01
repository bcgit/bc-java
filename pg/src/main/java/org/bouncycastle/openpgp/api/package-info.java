/**
 * The <pre>api</pre> package contains a high-level OpenPGP API layer on top of the
 * <pre>openpgp</pre> mid-level API.
 * It is tailored to provide a modern OpenPGP experience, following the guidance from rfc9580 ("OpenPGP v6"),
 * while also being interoperable with rfc4880 ("OpenPGP v4").
 * <p>
 * From an architectural point of view, the hierarchy of the individual layers is as follows:
 * <ul>
 *     <li>
 *         <pre>api</pre> specifies a high-level API using mid-level implementations from <pre>openpgp</pre>.
 *         This layer strives to be easy to use, hard to misuse and secure by default.
 *     </li>
 *     <li>
 *         <pre>openpgp</pre> defines a powerful, flexible, but quite verbose API using packet definitions
 *         from <pre>bcpg</pre>.
 *     </li>
 *     <li>
 *         <pre>bcpg</pre> implements serialization / deserialization of OpenPGP packets.
 *         It does not contain any business logic.
 *     </li>
 * </ul>
 */
package org.bouncycastle.openpgp.api;