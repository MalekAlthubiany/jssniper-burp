gradle/wrapper/gradle-wrapper.properties:

distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-7.6-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists

---

settings.gradle:

rootProject.name = 'jssniper'
include 'jssniper-extension'

---

.gradle/gradle.properties:

org.gradle.daemon=true
org.gradle.caching=true
org.gradle.parallel=true
org.gradle.workers.max=4
org.gradle.jvmargs=-Xmx1024m

---

BUILD INSTRUCTIONS

Prerequisites for Building

System Requirements:
- Operating System: Windows, macOS, or Linux
- Java Development Kit: Version 11 or higher
  Download from: https://adoptium.net/
  Verify: java -version
- Gradle: Version 7.0 or higher (wrapper included)
  Verify: gradle --version
- Git: For cloning repository

Initial Setup

1. Clone Repository:
git clone https://github.com/PortSwigger/jssniper-burp.git
cd jssniper-burp

2. Verify Java Installation:
java -version
Output should show Java 11 or higher

3. Check Gradle Wrapper:
The repository includes gradle wrapper (gradlew command)
./gradlew --version  (Linux/macOS)
gradlew --version   (Windows)

Building the Extension

Option 1: Using Gradle Wrapper (Recommended)

Linux/macOS:
./gradlew clean build

Windows:
gradlew.bat clean build

Expected Output:
BUILD SUCCESSFUL in Xs
Generated: build/libs/jssniper-2.0.0.jar

Option 2: Using System Gradle

Ensure Gradle 7.0+ installed:
gradle clean build

Option 3: Specific Tasks

Clean Build:
./gradlew clean

Compile Only:
./gradlew compileJava

Run Tests:
./gradlew test

Build JAR Only:
./gradlew jar

Build with Detailed Output:
./gradlew build --info

Build Output

After successful build:

Location: build/libs/
Filename: jssniper-2.0.0.jar
Size: Approximately 2-3 MB (with dependencies)
Ready for: Installation in Burp Suite

Verify Build

Check File Exists:
ls -la build/libs/jssniper-2.0.0.jar  (Linux/macOS)
dir build\libs\jssniper-2.0.0.jar     (Windows)

Verify JAR Contents:
jar tf build/libs/jssniper-2.0.0.jar | head -20

Check Manifest:
unzip -p build/libs/jssniper-2.0.0.jar META-INF/MANIFEST.MF

Installation After Building

1. Open Burp Suite
2. Navigate to Extender tab -> Extensions
3. Click "Add"
4. Select "Extension Type: Java"
5. Browse to: build/libs/jssniper-2.0.0.jar
6. Click "Next"
7. Extension loads automatically
8. JSSniper tab appears in main window

Troubleshooting Build Issues

Issue: "Gradle daemon not responding"
Solution:
./gradlew --stop
./gradlew clean build

Issue: "Cannot find JDK"
Solution:
export JAVA_HOME=/path/to/jdk/11  (Linux/macOS)
set JAVA_HOME=C:\path\to\jdk\11   (Windows)
./gradlew build

Issue: "Dependency resolution failed"
Solution:
./gradlew build --refresh-dependencies

Issue: "Out of memory during build"
Solution:
export GRADLE_OPTS="-Xmx2g"  (Linux/macOS)
set GRADLE_OPTS=-Xmx2g       (Windows)
./gradlew build

Issue: "Permission denied" (Linux/macOS)
Solution:
chmod +x gradlew
./gradlew build

Development Workflow

Setting Up IDE

IntelliJ IDEA:
1. File -> Open Project
2. Select jssniper-burp directory
3. IDEA detects Gradle project automatically
4. Wait for indexing to complete
5. Run -> Edit Configurations -> Add Application

Eclipse:
1. File -> Import -> Gradle -> Existing Gradle Project
2. Select jssniper-burp directory
3. Eclipse imports Gradle configuration
4. Project -> Build Project

Visual Studio Code:
1. Open folder: File -> Open Folder
2. Install Extension Pack for Java
3. Open Terminal
4. Run: ./gradlew build

Building from IDE

IntelliJ:
Build -> Build Project
Build -> Build Module 'jssniper'
Run -> Run (to test in Burp)

Eclipse:
Project -> Build Project
Project -> Clean...

VS Code:
Terminal -> Run Task -> gradle build

Continuous Development

Faster Build Cycle:
./gradlew build --offline  (if dependencies cached)
./gradlew build -x test    (skip tests for speed)
./gradlew jar --parallel   (parallel compilation)

Watch for Changes (experimental):
./gradlew build --continuous

Code Formatting:
./gradlew spotlessApply    (if formatter configured)

Code Quality Checks

Run Tests:
./gradlew test

View Test Results:
build/reports/tests/test/index.html

Code Analysis:
./gradlew check

Generate Documentation:
./gradlew javadoc

Build Report:
build/reports/

Advanced Build Options

Custom Gradle Properties

Create: gradle.properties
Add:

# Build Configuration
org.gradle.jvmargs=-Xmx1024m
org.gradle.daemon=true
org.gradle.parallel=true

# Custom Properties
burp_version=2024.8

Release Build

Create Release JAR:
./gradlew build -P release=true

Sign JAR (if configured):
./gradlew signArchives

Create Distribution:
./gradlew distZip

Publishing

Publish to Maven Local:
./gradlew publishToMavenLocal

Publish to Repository:
./gradlew publish

Dependency Management

View Dependencies:
./gradlew dependencies

View Dependency Tree:
./gradlew dependencyTree

Update Dependencies:
./gradlew dependencyUpdates

Check Vulnerabilities:
./gradlew dependencyCheckAnalyze

Gradle Wrapper Maintenance

Update Gradle Version:
./gradlew wrapper --gradle-version=7.6

Verify Wrapper:
./gradlew --version

Upgrade All Tools:
./gradlew wrapper --distribution-type=all

Performance Optimization

Parallel Builds:
./gradlew build --parallel --max-workers=4

Daemon Mode:
./gradlew build --daemon

Build Cache:
./gradlew build --build-cache

Offline Mode (if dependencies cached):
./gradlew build --offline

Clean Cache:
./gradlew cleanBuildCache

Docker Build

Build in Container:
docker build -t jssniper-builder .
docker run --rm -v $(pwd):/workspace jssniper-builder ./gradlew build

Dockerfile Example:
FROM openjdk:11-jdk-slim
RUN apt-get update && apt-get install -y gradle git
WORKDIR /workspace
COPY . .
RUN ./gradlew build

CI/CD Integration

GitHub Actions Workflow Example:

name: Build JSSniper
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-java@v2
        with:
          java-version: '11'
      - run: ./gradlew build
      - uses: actions/upload-artifact@v2
        with:
          name: jssniper-jar
          path: build/libs/jssniper-*.jar

GitLab CI:
build:
  stage: build
  image: openjdk:11-jdk-slim
  script:
    - apt-get update && apt-get install -y gradle
    - gradle build
  artifacts:
    paths:
      - build/libs/jssniper-*.jar

Build Signing

Generate Key:
keytool -genkey -alias jssniper-key -keyalg RSA -keystore jssniper.jks -validity 365

Configure Signing (build.gradle):
signing {
    sign configurations.archives
}

Sign on Build:
./gradlew build signArchives

Troubleshooting Build Verification

Verify JAR Size:
File should be 2-3 MB with all dependencies

Verify Main-Class:
jar xf build/libs/jssniper-2.0.0.jar META-INF/MANIFEST.MF
grep Main-Class META-INF/MANIFEST.MF

Test Manifest:
unzip -t build/libs/jssniper-2.0.0.jar

Class Verification:
jar tf build/libs/jssniper-2.0.0.jar | grep BurpExtension

Dependency Verification:
jar tf build/libs/jssniper-2.0.0.jar | grep "\.class$" | wc -l

Build Cleanup

Remove Build Output:
./gradlew clean

Remove Gradle Cache:
rm -rf ~/.gradle/caches  (Linux/macOS)
rmdir /s %USERPROFILE%\.gradle\caches  (Windows)

Reset IDE Cache:
IntelliJ: File -> Invalidate Caches
Eclipse: Project -> Clean All Projects

Full Reset:
./gradlew clean
rm -rf .gradle
./gradlew build

Release Build Checklist

Before Release Build:
[ ] All tests passing: ./gradlew test
[ ] Code compiled without warnings
[ ] Documentation updated
[ ] Version number correct in build.gradle
[ ] Dependencies up to date
[ ] Security checks passed
[ ] Performance verified

Create Release:
./gradlew build
Generate release notes
Tag in Git: git tag -a v2.0.0
Upload JAR to releases

Post-Release:
[ ] Update GitHub releases page
[ ] Announce in documentation
[ ] Update website/wiki
[ ] Close relevant issues
[ ] Plan next version

Quick Reference

Gradle Commands Summary:

./gradlew build              # Full build and test
./gradlew clean              # Remove build output
./gradlew test               # Run tests only
./gradlew compileJava        # Compile only
./gradlew jar                # Build JAR only
./gradlew clean build -x test # Build without tests (faster)
./gradlew build --info       # Detailed output
./gradlew build --scan       # Build with Gradle scan
./gradlew --version          # Show Gradle version
./gradlew tasks              # List all tasks
./gradlew help               # Show help

Expected Output:

BUILD SUCCESSFUL in 30s
10 actionable tasks: 10 executed

Generated Files:
build/classes/java/main/  - Compiled classes
build/libs/               - JAR files
build/reports/            - Test reports
build/tmp/                - Temporary files

Support

Build Issues: GitHub Issues
Gradle Documentation: https://docs.gradle.org/
Java Documentation: https://docs.oracle.com/javase/11/docs/
Montoya API: https://portswigger.net/burp/documentation/desktop/extend-burp/montoya-api

---

Your build is ready for Burp Suite installation!
