const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

class FDroidSigner {
    constructor(options = {}) {
        this.keystorePath = options.keystorePath || process.env.FDROID_KEYSTORE_PATH || path.join(__dirname, '..', 'config', 'fdroid-repo.keystore');
        this.certPath = options.certPath || process.env.FDROID_CERT_PATH || path.join(__dirname, '..', 'config', 'fdroid-repo.crt');
        this.keyPath = options.keyPath || process.env.FDROID_KEY_PATH || path.join(__dirname, '..', 'config', 'fdroid-repo.key');
        this.storepass = options.storepass || process.env.FDROID_KEYSTORE_PASSWORD || 'gplmods-fdroid-repo-pass';
        this.keypass = options.keypass || process.env.FDROID_KEY_PASSWORD || 'gplmods-fdroid-repo-pass';
        this.alias = options.alias || process.env.FDROID_KEY_ALIAS || 'gplmods';
        this.dname = options.dname || 'CN=GPL Mods Android, OU=F-Droid Repo, O=GPL Mods, C=US';

        this.keytoolPath = this.findCliTool('keytool');
        this.jarsignerPath = this.findCliTool('jarsigner');
        this.opensslPath = this.findCliTool('openssl');

        this.initialized = false;
        this.engine = 'none';
        this.fingerprint = '';
        this.formattedFingerprint = '';
        this.pubkeyHex = '';
    }

    findCliTool(toolName) {
        const isWin = process.platform === 'win32';
        const exeName = isWin ? `${toolName}.exe` : toolName;

        // 1. Explicit env override
        const envMap = {
            jarsigner: 'FDROID_JARSIGNER_PATH',
            keytool: 'FDROID_KEYTOOL_PATH',
            openssl: 'FDROID_OPENSSL_PATH'
        };
        const envKey = envMap[toolName];
        if (envKey && process.env[envKey] && fs.existsSync(process.env[envKey])) {
            return process.env[envKey];
        }

        // 2. JAVA_HOME for Java tools
        if ((toolName === 'keytool' || toolName === 'jarsigner') && process.env.JAVA_HOME) {
            const candidate = path.join(process.env.JAVA_HOME, 'bin', exeName);
            if (fs.existsSync(candidate)) return candidate;
        }

        // 3. Check Windows standard locations
        if (isWin) {
            const programFiles = [
                process.env['ProgramFiles'],
                process.env['ProgramFiles(x86)'],
                'C:\\Program Files',
                'C:\\Program Files (x86)'
            ].filter(Boolean);

            if (toolName === 'keytool' || toolName === 'jarsigner') {
                for (const pf of programFiles) {
                    const javaDir = path.join(pf, 'Java');
                    if (fs.existsSync(javaDir)) {
                        try {
                            const subdirs = fs.readdirSync(javaDir);
                            const jdkDirs = subdirs.filter(s => /jdk/i.test(s)).sort().reverse();
                            const otherDirs = subdirs.filter(s => !/jdk/i.test(s)).sort().reverse();
                            for (const subdir of [...jdkDirs, ...otherDirs]) {
                                const candidate = path.join(javaDir, subdir, 'bin', exeName);
                                if (fs.existsSync(candidate)) return candidate;
                            }
                        } catch (e) {}
                    }
                }
            } else if (toolName === 'openssl') {
                // Check Git's bundled OpenSSL on Windows
                for (const pf of programFiles) {
                    const gitCandidate = path.join(pf, 'Git', 'usr', 'bin', 'openssl.exe');
                    if (fs.existsSync(gitCandidate)) return gitCandidate;
                }
            }
        }

        // 4. Check system PATH
        try {
            const cmd = isWin ? `where ${exeName}` : `which ${exeName}`;
            const output = execSync(cmd, { stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
            const firstLine = output.split(/\r?\n/)[0];
            if (firstLine && fs.existsSync(firstLine)) return firstLine;
        } catch (e) {}

        // 5. Standard Linux paths
        const linuxCandidates = [
            `/usr/bin/${exeName}`,
            `/usr/local/bin/${exeName}`,
            `/usr/lib/jvm/default-java/bin/${exeName}`
        ];
        for (const p of linuxCandidates) {
            if (fs.existsSync(p)) return p;
        }

        return null;
    }

    init() {
        if (this.initialized) return;

        const configDir = path.dirname(this.keystorePath);
        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir, { recursive: true });
        }

        // 1. Ensure permanent Elliptic Curve keys & certificate exist
        if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
            if (this.keytoolPath && !fs.existsSync(this.keystorePath)) {
                console.log(`[F-Droid Signer] Generating permanent EC repository keystore at: ${this.keystorePath}`);
                try {
                    const genCmd = `"${this.keytoolPath}" -genkeypair -alias "${this.alias}" -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -validity 10000 -storetype PKCS12 -keystore "${this.keystorePath}" -storepass "${this.storepass}" -keypass "${this.keypass}" -dname "${this.dname}" -ext BasicConstraints=ca:false -ext KeyUsage=digitalSignature -ext ExtendedKeyUsage=codeSigning`;
                    execSync(genCmd, { stdio: 'pipe' });
                } catch (err) {
                    console.error('[F-Droid Signer] Failed to generate EC keystore:', err);
                }
            }

            // Export PEM files if keystore exists
            if (fs.existsSync(this.keystorePath)) {
                if (this.keytoolPath && !fs.existsSync(this.certPath)) {
                    try {
                        const exportCertCmd = `"${this.keytoolPath}" -exportcert -alias "${this.alias}" -keystore "${this.keystorePath}" -storepass "${this.storepass}" -rfc`;
                        const certPem = execSync(exportCertCmd, { stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' });
                        fs.writeFileSync(this.certPath, certPem, 'utf8');
                    } catch (e) {}
                }
                if (this.opensslPath && !fs.existsSync(this.keyPath)) {
                    try {
                        const exportKeyCmd = `"${this.opensslPath}" pkcs12 -in "${this.keystorePath}" -passin pass:"${this.storepass}" -nocerts -nodes -out "${this.keyPath}"`;
                        execSync(exportKeyCmd, { stdio: 'pipe' });
                    } catch (e) {}
                }
            } else if (this.opensslPath && !fs.existsSync(this.keyPath) && !fs.existsSync(this.certPath)) {
                // Generate directly with openssl if keytool was absent
                try {
                    execSync(`"${this.opensslPath}" ecparam -name prime256v1 -genkey -noout -out "${this.keyPath}"`, { stdio: 'pipe' });
                    execSync(`"${this.opensslPath}" req -new -x509 -key "${this.keyPath}" -out "${this.certPath}" -days 10000 -subj "/CN=GPL Mods Android/OU=F-Droid Repo/O=GPL Mods/C=US" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=codeSigning"`, { stdio: 'pipe' });
                } catch (e) {}
            }
        }

        // 2. Read certificate and populate repository fingerprint & public key
        try {
            let certPem = '';
            if (fs.existsSync(this.certPath)) {
                certPem = fs.readFileSync(this.certPath, 'utf8');
            } else if (this.keytoolPath && fs.existsSync(this.keystorePath)) {
                const exportCmd = `"${this.keytoolPath}" -exportcert -alias "${this.alias}" -keystore "${this.keystorePath}" -storepass "${this.storepass}" -rfc`;
                certPem = execSync(exportCmd, { stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' });
                fs.writeFileSync(this.certPath, certPem, 'utf8');
            }

            if (certPem) {
                const cert = new crypto.X509Certificate(certPem);
                this.formattedFingerprint = cert.fingerprint256.toUpperCase();
                this.fingerprint = this.formattedFingerprint.replace(/:/g, '');
                this.pubkeyHex = cert.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
                this.initialized = true;
            }
        } catch (err) {
            console.error('[F-Droid Signer] Failed to read certificate:', err);
        }

        // 3. Determine primary cryptographic signing engine
        if (this.jarsignerPath && fs.existsSync(this.keystorePath)) {
            this.engine = 'jarsigner';
        } else if (this.opensslPath && fs.existsSync(this.certPath) && fs.existsSync(this.keyPath)) {
            this.engine = 'openssl';
        } else {
            this.engine = 'manifest-only';
            console.warn('[F-Droid Signer] Neither jarsigner nor openssl found. Repo JARs will be manifest-attributed.');
        }

        console.log(`[F-Droid Signer] Signing engine initialized (Mode: ${this.engine}).`);
        console.log(`[F-Droid Signer] Fingerprint (SHA-256): ${this.fingerprint}`);
    }

    /**
     * Formats a manifest line adhering strictly to standard 72-byte line wrapping.
     */
    formatManifestLine(line) {
        if (line.length <= 70) return line + '\r\n';
        let res = '';
        let remaining = line;
        res += remaining.slice(0, 70) + '\r\n';
        remaining = remaining.slice(70);
        while (remaining.length > 0) {
            res += ' ' + remaining.slice(0, 69) + '\r\n';
            remaining = remaining.slice(69);
        }
        return res;
    }

    /**
     * Signs an AdmZip instance using jarsigner or openssl CMS.
     * Ensures exactly 1 single code signer per entry for strict Droid-ify / Neo-Store verification.
     */
    signZip(admZip) {
        if (!this.initialized) {
            this.init();
        }

        // Extract non-META-INF entries cleanly
        const rawEntries = admZip.getEntries().filter(e => !e.isDirectory && !e.entryName.startsWith('META-INF/'));
        const cleanZip = new AdmZip(undefined, { noSort: true });
        const entries = [];
        for (const entry of rawEntries) {
            const data = entry.getData();
            cleanZip.addFile(entry.entryName, data);
            entries.push({ name: entry.entryName, data });
        }

        // 1. Try JARSIGNER engine (Java JDK)
        if (this.engine === 'jarsigner' || (this.jarsignerPath && fs.existsSync(this.keystorePath))) {
            const tempId = `fdroid-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
            const tmpJarPath = path.join(os.tmpdir(), `${tempId}.jar`);

            try {
                cleanZip.writeZip(tmpJarPath);
                const signCmd = `"${this.jarsignerPath}" -keystore "${this.keystorePath}" -storepass "${this.storepass}" -keypass "${this.keypass}" -sigalg SHA256withECDSA -digestalg SHA-256 "${tmpJarPath}" "${this.alias}"`;
                execSync(signCmd, { stdio: 'pipe' });
                return fs.readFileSync(tmpJarPath);
            } catch (err) {
                console.warn('[F-Droid Signer] Jarsigner failed, trying OpenSSL fallback:', err.message);
            } finally {
                if (fs.existsSync(tmpJarPath)) {
                    try { fs.unlinkSync(tmpJarPath); } catch (e) {}
                }
            }
        }

        // 2. Try OPENSSL engine (Standard on Render / Linux and Git on Windows)
        if (this.opensslPath && fs.existsSync(this.certPath) && fs.existsSync(this.keyPath)) {
            try {
                return this.signWithOpenSsl(entries);
            } catch (err) {
                console.error('[F-Droid Signer] OpenSSL signing failed:', err);
            }
        }

        // 3. Fallback
        return this.createFallbackAttributedJar(admZip);
    }

    /**
     * Signs a JAR using OpenSSL CMS detached signature (.EC file).
     * Fully compliant with Java Signed JAR specification and Android's JarVerifier.
     */
    signWithOpenSsl(entries) {
        const aliasUpper = (this.alias || 'GPLMODS').toUpperCase().replace(/[^A-Z0-9_-]/g, '');

        // 1. Generate META-INF/MANIFEST.MF
        const mainSection = 'Manifest-Version: 1.0\r\nCreated-By: 1.0 (GPLMods F-Droid Engine)\r\n\r\n';
        let manifest = mainSection;
        const entryDigests = [];

        for (const entry of entries) {
            const fileHash = crypto.createHash('sha256').update(entry.data).digest('base64');
            const section = this.formatManifestLine(`Name: ${entry.name}`) +
                            this.formatManifestLine(`SHA-256-Digest: ${fileHash}`) +
                            '\r\n';
            manifest += section;

            const secHash = crypto.createHash('sha256').update(Buffer.from(section, 'utf8')).digest('base64');
            entryDigests.push({ name: entry.name, secHash });
        }

        const manifestBuffer = Buffer.from(manifest, 'utf8');
        const manifestHash = crypto.createHash('sha256').update(manifestBuffer).digest('base64');
        const mainAttrsHash = crypto.createHash('sha256').update(Buffer.from(mainSection, 'utf8')).digest('base64');

        // 2. Generate META-INF/<ALIAS>.SF with Main-Attributes digest
        let sf = 'Signature-Version: 1.0\r\nCreated-By: 1.0 (GPLMods F-Droid Engine)\r\n' +
                 this.formatManifestLine(`SHA-256-Digest-Manifest: ${manifestHash}`) +
                 this.formatManifestLine(`SHA-256-Digest-Manifest-Main-Attributes: ${mainAttrsHash}`) +
                 '\r\n';

        for (const item of entryDigests) {
            sf += this.formatManifestLine(`Name: ${item.name}`) +
                  this.formatManifestLine(`SHA-256-Digest: ${item.secHash}`) +
                  '\r\n';
        }
        const sfBuffer = Buffer.from(sf, 'utf8');

        // 3. Sign .SF file using OpenSSL CMS detached signature (eContent is absent per Jar specification)
        const tempId = `fdroid-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const tmpSfPath = path.join(os.tmpdir(), `${tempId}.SF`);
        const tmpEcPath = path.join(os.tmpdir(), `${tempId}.EC`);

        let ecBuffer;
        try {
            fs.writeFileSync(tmpSfPath, sfBuffer);
            // No -nodetach flag -> produces detached signature block where eContent is ABSENT
            const opensslCmd = `"${this.opensslPath}" cms -sign -in "${tmpSfPath}" -signer "${this.certPath}" -inkey "${this.keyPath}" -outform DER -binary -out "${tmpEcPath}"`;
            execSync(opensslCmd, { stdio: 'pipe' });
            ecBuffer = fs.readFileSync(tmpEcPath);
        } finally {
            if (fs.existsSync(tmpSfPath)) {
                try { fs.unlinkSync(tmpSfPath); } catch (e) {}
            }
            if (fs.existsSync(tmpEcPath)) {
                try { fs.unlinkSync(tmpEcPath); } catch (e) {}
            }
        }

        // 4. Assemble signed JAR with META-INF FIRST, using { noSort: true } to guarantee order
        const signedZip = new AdmZip(undefined, { noSort: true });
        signedZip.addFile('META-INF/MANIFEST.MF', manifestBuffer);
        signedZip.addFile(`META-INF/${aliasUpper}.SF`, sfBuffer);
        signedZip.addFile(`META-INF/${aliasUpper}.EC`, ecBuffer);

        for (const entry of entries) {
            signedZip.addFile(entry.name, entry.data);
        }

        return signedZip.toBuffer();
    }

    createFallbackAttributedJar(admZip) {
        const entries = admZip.getEntries().filter(e => !e.isDirectory && !e.entryName.startsWith('META-INF/'));
        let manifest = 'Manifest-Version: 1.0\r\nCreated-By: 1.0 (GPLMods F-Droid Engine)\r\n\r\n';

        for (const entry of entries) {
            const hash = crypto.createHash('sha256').update(entry.getData()).digest('base64');
            manifest += `Name: ${entry.entryName}\r\nSHA-256-Digest: ${hash}\r\n\r\n`;
        }

        const fallbackZip = new AdmZip(undefined, { noSort: true });
        fallbackZip.addFile('META-INF/MANIFEST.MF', Buffer.from(manifest, 'utf8'));
        for (const entry of entries) {
            fallbackZip.addFile(entry.entryName, entry.getData());
        }

        return fallbackZip.toBuffer();
    }
}

const instance = new FDroidSigner();
instance.init();

module.exports = instance;
