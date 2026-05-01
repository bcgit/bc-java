# Bouncy Castle Java API How To
## Using Bouncy Castle with GraalVM Native Image
### Problem: Provider Not Registered at Build Time with `UnsupportedFeatureError` Exception
#### Error message
```text
Trying to verify a provider that was not registered at build time: BC version...
```
#### Cause:
Bouncy Castle security provider isn't properly registered during GraalVM native image build process.

### Solution 1: Static Initializer Approach (No GraalVM SDK)
#### Step 1. Create Initializer Class 
```java
package com.yourpackage.crypto;  // ← Replace with your actual package

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class BCInitializer {
    static {
        // Force provider registration during image build
        Security.addProvider(new BouncyCastleProvider());
    }
}
```

#### Step 2. And then in the native-image build configuration 
For Maven (`pom.xml`)
```xml
<plugin>
    <groupId>org.graalvm.buildtools</groupId>
    <artifactId>native-maven-plugin</artifactId>
    <version>0.9.28</version>
    <configuration>
        <buildArgs>
            <!-- Initialize Bouncy Castle and our initializer -->
            <arg>--initialize-at-build-time=org.bouncycastle,com.yourpackage.crypto.BCInitializer</arg>
            <!-- Required for SecureRandom components -->
            <arg>--initialize-at-run-time=org.bouncycastle.jcajce.provider.drbg.DRBG$Default,org.bouncycastle.jcajce.provider.drbg.DRBG$NonceAndIV</arg>
        </buildArgs>
    </configuration>
</plugin>
```

For Gradle (`build.gradle`),
```gradle
    buildArgs.add('--initialize-at-build-time=com.yourpackage.crypto.BCInitializer')
    buildArgs.add("--initialize-at-run-time=org.bouncycastle.jcajce.provider.drbg.DRBG\$Default,org.bouncycastle.jcajce.provider.drbg.DRBG\$NonceAndIV")
```
# Key Configuration

| Argument                        | Purpose                                                         |
| ------------------------------- |-----------------------------------------------------------------|
| `--initialize-at-build-time`    | Forces inclusion of BC classes and triggers static initializer. |
| `--initialize-at-run-time`      | Solves stateful SecureRandom initialization issues.             |
|`--enable-all-security-services`	| (optional) Enables JCE security infrastructure                  |


### Solution 2: GraalVM Feature Approach (With SDK)

#### Step 1: Create a Native Image Feature
```java
package com.yourpackage.crypto;  // ← Replace with your actual package

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.graalvm.nativeimage.hosted.Feature;

import java.security.Security;

/**
 * A GraalVM Feature that registers the Bouncy Castle provider.
 * This is required so that native image builds verify and include the provider.
 */
public class BouncyCastleFeature implements Feature {
    
    @Override
    public void afterRegistration(AfterRegistrationAccess access) {
        // Register the Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }
}
```

#### Step 2: Configure Dependencies and Build
##### 2.1 add dependency
```xml
<dependency>
    <groupId>org.graalvm.sdk</groupId>
    <artifactId>graal-sdk</artifactId>
    <version>21.0.0</version> <!-- Match your GraalVM version -->
    <scope>provided</scope>
</dependency>
```
##### 2.2 add plugin
```xml
<plugin>
    <groupId>org.graalvm.buildtools</groupId>
    <artifactId>native-maven-plugin</artifactId>
    <version>0.9.28</version>
    <configuration>
        <buildArgs>
            <arg>--features=com.yourpackage.crypto.BouncyCastleFeature</arg>  <!-- replace with correct package path -->
            <arg>--initialize-at-build-time=org.bouncycastle</arg>
            <arg>--initialize-at-run-time=org.bouncycastle.jcajce.provider.drbg.DRBG$Default,org.bouncycastle.jcajce.provider.drbg.DRBG$NonceAndIV</arg>
        </buildArgs>
    </configuration>
</plugin>
```
Key Configuration Explanations:
`--features=...`
- Registers custom feature class that adds BouncyCastle provider at build time
- Required for JCE security provider verification

### Troubleshooting
#### Common Issues
##### Classpath Conflicts:

```text
Error: Class-path entry contains class from image builder
```
Fix: Add `-H:+AllowDeprecatedBuilderClassesOnImageClasspath` (temporary) or ensure graal-sdk has provided scope

##### Missing Algorithms:
Example of the error message:
```text
No such algorithm: AES/CBC/PKCS5Padding
```

Fix: Verify `--initialize-at-build-time` includes `org.bouncycastle`