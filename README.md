# The Bouncy Castle Crypto Package For Java

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a support contract through [Crypto Workshop](https://www.keyfactor.com/platform/bouncy-castle-support/) (now part of Keyfactor).

The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/). 

**Note**: this source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please contact us directly at  [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Using Bouncy Castle in your project

The Bouncy Castle artifacts are published to [Maven Central](https://central.sonatype.com/search?q=g%3Aorg.bouncycastle) under the `org.bouncycastle` group. Pick the artifacts you need, then add them to your build using the latest released version.

For the lightweight crypto API plus the JCA/JCE provider — the most common starting point — add `bcprov-jdk18on`:

**Maven**:

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.84</version>
</dependency>
```

**Gradle**:

```groovy
implementation 'org.bouncycastle:bcprov-jdk18on:1.84'
```

If you need functionality beyond what `bcprov` provides, add the appropriate companion artifacts. They all share the same `org.bouncycastle` group, the same `-jdk18on` suffix, and the same version — pull each one in the same way as the snippets above:

| Artifact | What it covers |
| -------- | -------------- |
| `bcprov-jdk18on`   | Lightweight crypto API plus the `BC` / `BCPQC` JCA/JCE providers. Required by every other module. |
| `bcpkix-jdk18on`   | X.509 / PKCS#10 / PKCS#12, CMS, S/MIME helpers (top-level only), TSP, OCSP, CMP / CRMF, certificate path validation. |
| `bcpg-jdk18on`     | OpenPGP (RFC 4880 / RFC 9580). |
| `bctls-jdk18on`    | Standalone TLS 1.0 – 1.3 implementation plus the BCJSSE provider. |
| `bcmail-jdk18on`   | S/MIME built on top of `bcpkix`, targeting the legacy `javax.mail` / `javax.activation` 1.x runtimes. |
| `bcjmail-jdk18on`  | S/MIME for the Jakarta runtimes (`jakarta.mail` / `jakarta.activation` 2.x). Pick this for modern Spring Boot / Quarkus / Jakarta EE apps, and use `bcmail-jdk18on` for the older `javax.*` stack. |
| `bcmls-jdk18on`    | Messaging Layer Security (RFC 9420). |
| `bcutil-jdk18on`   | Shared ASN.1 utility classes used by `bcpkix`. Pulled in transitively. |

### Suffix history

The `-jdk18on` suffix means "JDK 1.8 and newer." Pre-1.71 releases shipped under a `-jdk15on` suffix (JDK 1.5 and newer); those artifacts are end-of-life and should not be used for new development. The `15to18` suffix you may see in this repository's local Gradle outputs reflects a transitional build flavour and is **not** what is published to Maven Central.

### FIPS distribution

The FIPS-certified BC distribution lives in a separate source tree with separate Maven coordinates and a separate licence — it is not what this repository builds. See [the BC FIPS page](https://www.bouncycastle.org/fips-java/) or contact [office@bouncycastle.org](mailto:office@bouncycastle.org) for additional details.

## Maven Public Key

The file [bc_maven_public_key.asc](bc_maven_public_key.asc) contains the public key used to sign our artifacts on Maven Central. You will need to use 

```
gpg -o bc_maven_public_key.gpg --dearmor bc_maven_public_key.asc
```

to dearmor the key before use. Once that is done, a file can be verified by using:

```
gpg --no-default-keyring --keyring ./bc_maven_public_key.gpg --verify  file_name.jar.asc file_name.jar
```

Note: the ./ is required in front of the key file name to tell gpg to look locally.

## Building overview

Building the project requires JDK 25 or later to drive Gradle — make sure JAVA_HOME (or whatever JVM ```gradlew``` picks up) points at a JDK 25+ installation.

If the build script detects BC_JDK8, BC_JDK11, BC_JDK17, BC_JDK21, BC_JDK25 it will add to the usual test task a dependency on test tasks
that specifically use the JVMs addressed by those environmental variables.

To run the tests of the project as part of the build test data is needed. Our test data can be found at the [bc-test-data](https://github.com/bcgit/bc-test-data) repository. The tests locate the bc-test-data tree using, in order:

1. The system property ```bc.test.data.home```, if set.
2. The environment variable ```BC_TEST_DATA_HOME```, if set.
3. Otherwise the tests walk up from the working directory looking for a directory literally named ```bc-test-data```. The simplest configuration is therefore to check ```bc-test-data``` out as a sibling of ```bc-java``` and no further setup is required.

When the property or environment variable is supplied, the named path is required to exist; a mistyped value fails fast with a ```FileNotFoundException``` naming whichever source supplied it, rather than silently falling through to the walk-up.

We support testing on specific JVMs as it is the only way to be certain the library is compatible.

## Environmental Variables

The following environmental variables can optionally point to the JAVA_HOME for each JVM version.

```
export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
export BC_JDK21=/path/to/java21
export BC_JDK25=/path/to/java25
```

If your ```bc-test-data``` checkout is not a sibling of ```bc-java```, set ```BC_TEST_DATA_HOME``` (or pass ```-Dbc.test.data.home=...``` on the command line) so the tests can find it:

```
export BC_TEST_DATA_HOME=/path/to/bc-test-data
```

## Building

The project now uses ```gradlew``` which can be invoked for example:

```
# from the root of the project

# Ensure JAVA_HOME points to JDK 25 or higher JAVA_HOME or that
# gradlew can find a java 25 installation to use.


./gradlew clean build

```

At startup the gradle script prints which of the BC_JDK environmental variables it found; it does not verify that their values point at working JDK installations.

Each module's built jars are written to its own ```<module>/build/libs``` directory (e.g. ```prov/build/libs/bcprov-jdk18on-<version>.jar```). For convenience, a top-level ```copyJars``` task gathers the produced jars (main, sources and javadoc) for all published modules (```bccore```, ```bcutil```, ```bcprov```, ```bcpkix```, ```bcpg```, ```bctls```, ```bcmls```, ```bcmail```, ```bcjmail```) into a single ```dist``` directory at the project root:

```
./gradlew copyJars
```

A sibling ```copyMavenJars``` task produces the same set minus ```bccore``` (whose classes are already bundled into ```bcprov```), matching the artifacts published to Maven Central:

```
./gradlew copyMavenJars
```

## SBOM and CBOM generation

The build can produce CycloneDX 1.6 bills of materials describing the release artifacts:

```
./gradlew generateSbom     # -> build/reports/sbom/
./gradlew generateCbom     # -> build/reports/cbom/
```

```generateSbom``` writes a Software Bill of Materials ([CycloneDX SBOM](https://cyclonedx.org/capabilities/sbom/)) mirroring the published ```bc-jdk18on-bom``` Maven BOM: one library component per published module jar, with MD5 / SHA-1 / SHA-256 hashes matching the Maven repository checksum files, the declared external dependencies, and the inter-module dependency graph as it appears in the published poms. Alongside the SBOM itself (```bc-jdk18on-bom-<version>-cyclonedx.json```) the task copies in the BOM's ```.pom``` and Gradle Module Metadata ```.module``` files, so the output directory holds the complete publishable set for the BOM artifact. The component set is read from the ```bom``` project's platform constraints, so the SBOM and the published Maven BOM stay in lockstep automatically.

```generateCbom``` writes a Cryptographic Bill of Materials ([CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)) for the freshly built ```bcprov``` jar by introspecting the JCA service tables of the ```BC``` (```BouncyCastleProvider```) and ```BCPQC``` (```BouncyCastlePQCProvider```) providers: one ```cryptographic-asset``` component per algorithm, carrying its primitive classification (block cipher, signature, KEM, hash, MAC, KDF, DRBG, ...), the crypto functions it provides, and its OID(s), plus a ```provides``` dependency edge from the ```bcprov``` library component to every asset. The output is ```build/reports/cbom/bcprov-jdk18on-<version>-cyclonedx.json```.

Both BOMs are reproducible: the serial number is a name-based UUID derived from the artifact coordinates, and the timestamp is taken from the ```SOURCE_DATE_EPOCH``` environment variable when set, falling back to the git commit time recorded in the ```bccore``` sources jar manifest — so the same version yields byte-identical output.

## Multi-release jars and testing
Some subprojects produce multi-release jars and these jars are can be tested on different jvm versions specifically.

If the env vars are defined:
```
export BC_JDK8=/path/to/java8
export BC_JDK11=/path/to/java11
export BC_JDK17=/path/to/java17
export BC_JDK21=/path/to/java21
export BC_JDK25=/path/to/java25
```

The version-specific test tasks (```test11```, ```test15```, ```test17```, ```test25```, ...) only run when the BC_JDK variable for the JVM they run on is set (```test15``` runs on the BC_JDK17 JVM); if none of the variables are defined only the normal test task is run, on the JVM driving Gradle.


## Code Organisation

The clean room JCE, for use with JDK 1.1 to JDK 1.3 is in the jce/src/main/java directory. From JDK 1.4 and later the JCE ships with the JVM, the source for later JDKs follows the progress that was made in the later versions of the JCE. If you are using a later version of the JDK which comes with a JCE install please **do not** include the jce directory as a source file as it will clash with the JCE API installed with your JDK.

The **core** module provides all the functionality in the ligthweight APIs.

The **prov** module provides all the JCA/JCE provider functionality.

The **util** module is the home for code which is used by other modules that does not need to be in prov. At the moment this is largely ASN.1 classes for the PKIX module.

The **pkix** module is the home for code for X.509 certificate generation and the APIs for standards that rely on ASN.1 such
as CMS, TSP, PKCS#12, OCSP, CRMF, and CMP.

The **mail** module provides an S/MIME API built on top of CMS.

The **pg** module is the home for code used to support OpenPGP.

The **tls** module is the home for code used to a general TLS API and JSSE Provider.

The build scripts that come with the full distribution allow creation of the different releases by using the different source trees while excluding classes that are not appropriate and copying in the required compatibility classes from the directories containing compatibility classes appropriate for the distribution.

If you want to try create a build for yourself, using your own environment, the best way to do it is to start with the build for the distribution you are interested in, make sure that builds, and then modify your build scripts to do the required exclusions and file copies for your setup, otherwise you are likely to get class not found exceptions. The final caveat to this is that as the j2me distribution includes some compatibility classes starting in the java package, you need to use an obfuscator to change the package names before attempting to import a midlet using the BC API.

**Important**: You will also need to check out the [bc-test-data](https://github.com/bcgit/bc-test-data) repository at the same level as the bc-java repository if you want to run the tests.


## Examples and Tests

To view some examples, look at the test programs in the packages:

*   **org.bouncycastle.crypto.test**

*   **org.bouncycastle.jce.provider.test**

*   **org.bouncycastle.cms.test**

*   **org.bouncycastle.mail.smime.test**

*   **org.bouncycastle.openpgp.test**

*   **org.bouncycastle.tsp.test**

There are also some specific example programs for dealing with SMIME and OpenPGP. They can be found in:

*   **org.bouncycastle.mail.smime.examples**

*   **org.bouncycastle.openpgp.examples**

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-request@bouncycastle.org](mailto:announce-crypto-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-request@bouncycastle.org](mailto:dev-crypto-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback and Contributions

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org), if you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues here on github, or via feedback-crypto if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
