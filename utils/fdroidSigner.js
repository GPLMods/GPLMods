const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

class FDroidSigner {
    constructor(options = {}) {
        this.keystorePath = options.keystorePath || process.env.FDROID_KEYSTORE_PATH || path.join(__dirname, '..', 'config', 'fdroid-repo.keystore');
        this.storepass = options.storepass || process.env.FDROID_KEYSTORE_PASSWORD || 'gplmods-fdroid-repo-pass';
        this.keypass = options.keypass || process.env.FDROID_KEY_PASSWORD || 'gplmods-fdroid-repo-pass';
        this.alias = options.alias || process.env.FDROID_KEY_ALIAS || 'gplmods';
        this.dname = options.dname || 'CN=GPL Mods Android, OU=F-Droid Repo, O=GPL Mods, C=US';

        this.keytoolPath = this.findJavaTool('keytool');
        this.jarsignerPath = this.findJavaTool('jarsigner');
        this.initialized = false;
        this.fingerprint = '';
        this.formattedFingerprint = '';
        this.pubkeyHex = '';
    }

    findJavaTool(toolName) {
        const isWin = process.platform === 'win32';
        const exeName = isWin ? `${toolName}.exe` : toolName;

        // 1. Explicit env override
        const envKey = toolName === 'jarsigner' ? 'FDROID_JARSIGNER_PATH' : 'FDROID_KEYTOOL_PATH';
        if (process.env[envKey] && fs.existsSync(process.env[envKey])) {
            return process.env[envKey];
        }

        // 2. Check JAVA_HOME
        if (process.env.JAVA_HOME) {
            const candidate = path.join(process.env.JAVA_HOME, 'bin', exeName);
            if (fs.existsSync(candidate)) return candidate;
        }

        // 3. Check Windows Program Files (prioritize JDK versions over JRE)
        if (isWin) {
            const programFiles = [
                process.env['ProgramFiles'],
                process.env['ProgramFiles(x86)'],
                'C:\\Program Files',
                'C:\\Program Files (x86)'
            ].filter(Boolean);

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
        }

        // 4. Check system PATH
        try {
            const cmd = isWin ? `where ${exeName}` : `which ${exeName}`;
            const output = execSync(cmd, { stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
            const firstLine = output.split(/\r?\n/)[0];
            if (firstLine && fs.existsSync(firstLine)) return firstLine;
        } catch (e) {}

        // 5. Standard Linux paths
        const linuxPaths = [
            `/usr/bin/${exeName}`,
            `/usr/local/bin/${exeName}`,
            `/usr/lib/jvm/default-java/bin/${exeName}`
        ];
        for (const p of linuxPaths) {
            if (fs.existsSync(p)) return p;
        }

        return null;
    }

    init() {
        if (this.initialized) return;

        if (!this.keytoolPath || !this.jarsignerPath) {
            console.warn('[F-Droid Signer] Java tools (keytool / jarsigner) not found. Serving manifest-attributed JARs.');
            return;
        }

        const dir = path.dirname(this.keystorePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        // Generate persistent keystore if not already present
        if (!fs.existsSync(this.keystorePath)) {
            console.log(`[F-Droid Signer] Generating permanent repository keystore at: ${this.keystorePath}`);
            try {
                const genCmd = `"${this.keytoolPath}" -genkeypair -alias "${this.alias}" -keyalg RSA -keysize 2048 -validity 10000 -storetype PKCS12 -keystore "${this.keystorePath}" -storepass "${this.storepass}" -keypass "${this.keypass}" -dname "${this.dname}"`;
                execSync(genCmd, { stdio: 'pipe' });
                console.log('[F-Droid Signer] Repository keystore generated successfully.');
            } catch (err) {
                console.error('[F-Droid Signer] Failed to generate keystore:', err);
                return;
            }
        }

        // Export and parse certificate to extract SHA-256 fingerprint and SPKI pubkey
        try {
            const exportCmd = `"${this.keytoolPath}" -exportcert -alias "${this.alias}" -keystore "${this.keystorePath}" -storepass "${this.storepass}" -rfc`;
            const certPem = execSync(exportCmd, { stdio: ['pipe', 'pipe', 'ignore'], encoding: 'utf8' });
            const cert = new crypto.X509Certificate(certPem);

            this.formattedFingerprint = cert.fingerprint256.toUpperCase();
            this.fingerprint = this.formattedFingerprint.replace(/:/g, '');
            this.pubkeyHex = cert.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
            this.initialized = true;

            console.log(`[F-Droid Signer] Repository signing engine initialized.`);
            console.log(`[F-Droid Signer] Fingerprint (SHA-256): ${this.fingerprint}`);
        } catch (err) {
            console.error('[F-Droid Signer] Failed to read certificate from keystore:', err);
        }
    }

    /**
     * Signs an AdmZip instance using jarsigner.
     * If jarsigner is unavailable, injects standard MANIFEST.MF attributes so clients don't fail with No attributes.
     */
    signZip(admZip) {
        if (!this.initialized || !this.jarsignerPath) {
            return this.createFallbackAttributedJar(admZip);
        }

        const tempId = `fdroid-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const tmpJarPath = path.join(os.tmpdir(), `${tempId}.jar`);

        try {
            admZip.writeZip(tmpJarPath);

            // Execute jarsigner with standard SHA256withRSA and SHA-256 digest
            const signCmd = `"${this.jarsignerPath}" -keystore "${this.keystorePath}" -storepass "${this.storepass}" -keypass "${this.keypass}" -sigalg SHA256withRSA -digestalg SHA-256 "${tmpJarPath}" "${this.alias}"`;
            execSync(signCmd, { stdio: 'pipe' });

            return fs.readFileSync(tmpJarPath);
        } catch (err) {
            console.error('[F-Droid Signer] Error signing JAR with jarsigner:', err);
            return this.createFallbackAttributedJar(admZip);
        } finally {
            if (fs.existsSync(tmpJarPath)) {
                try { fs.unlinkSync(tmpJarPath); } catch (e) {}
            }
        }
    }

    /**
     * Fallback if jarsigner is not present: generates MANIFEST.MF containing
     * exact Name & SHA-256-Digest entries for each file in the archive to prevent
     * "No attributes for entry.json" error.
     */
    createFallbackAttributedJar(admZip) {
        const entries = admZip.getEntries().filter(e => !e.isDirectory && !e.entryName.startsWith('META-INF/'));
        let manifest = 'Manifest-Version: 1.0\r\nCreated-By: 1.0 (GPLMods F-Droid Engine)\r\n\r\n';

        for (const entry of entries) {
            const hash = crypto.createHash('sha256').update(entry.getData()).digest('base64');
            manifest += `Name: ${entry.entryName}\r\nSHA-256-Digest: ${hash}\r\n\r\n`;
        }

        const fallbackZip = new AdmZip();
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
