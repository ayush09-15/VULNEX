/**
 * VULNEX Security Regression Test Suite
 * Covers:
 * 1. SSRF Protection: Loopback, private IP ranges, cloud metadata, alternate formats, DNS rebinding, and redirects.
 * 2. ZIP Slip & Archive Security: Directory traversal, encoded escapes, absolute paths, symlinks, and zip bombs.
 * 3. Path Traversal & Workspace Confinement: Encoded traversal, absolute paths, symlink escapes in getFileExcerpt and diffValidator.
 */

const { describe, it, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

// Security modules & validators under test
const {
  isPrivateOrBlockedIPv4,
  isPrivateOrBlockedIPv6,
  parseNumericIp,
  isPrivateOrBlockedHost,
  validateSafeUrl,
  validateUrlAndResolveDns,
  validateRedirect,
  CLOUD_METADATA_HOSTS
} = require('../src/utils/ssrfGuard');

const {
  SafeHttpsRepoUrl,
  SafeRelativeFilePath
} = require('../src/validators/canonical.schema');

const { validateGitHubUrl } = require('../src/services/repository.service');
const { validateZipArchive, extractZipArchive } = require('../src/services/zip.service');
const { getFileExcerpt } = require('../src/services/inventory.service');
const { validateWorkspacePath, validateDiffAndPaths } = require('../src/validators/diffValidator');

// Helper to create isolated temporary directory
function createIsolatedTempDir(prefix = 'vulnex-sec-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ----------------------------------------------------------------------------
// 1. SSRF Protection & Safe URL Resolution Tests
// ----------------------------------------------------------------------------
describe('1. SSRF Protection & Safe URL Resolution', () => {

  describe('1.1 Localhost & Loopback Target Rejection', () => {
    const loopbackIps = [
      '127.0.0.1',
      '127.0.0.2',
      '127.1.2.3',
      '127.255.255.255',
      '0.0.0.0',
      '0.0.0.1'
    ];

    for (const ip of loopbackIps) {
      it(`blocks IPv4 loopback / local IP: ${ip}`, () => {
        assert.equal(isPrivateOrBlockedIPv4(ip), true, `Should block ${ip}`);
        assert.equal(isPrivateOrBlockedHost(ip), true, `isPrivateOrBlockedHost should block ${ip}`);

        const url = `https://${ip}/repo.git`;
        assert.equal(validateSafeUrl(url).isValid, false);
        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      });
    }

    const loopbackHosts = [
      'localhost',
      'LOCALHOST',
      'sub.localhost',
      'foo.bar.localhost'
    ];

    for (const host of loopbackHosts) {
      it(`blocks localhost domain: ${host}`, () => {
        assert.equal(isPrivateOrBlockedHost(host), true);
        const url = `https://${host}/repo.git`;
        assert.equal(validateSafeUrl(url).isValid, false);
        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      });
    }

    const ipv6Loopbacks = [
      '::1',
      '0:0:0:0:0:0:0:1',
      '::',
      '0:0:0:0:0:0:0:0'
    ];

    for (const ip of ipv6Loopbacks) {
      it(`blocks IPv6 loopback / unspecified: ${ip}`, () => {
        assert.equal(isPrivateOrBlockedIPv6(ip), true);
        assert.equal(isPrivateOrBlockedHost(`[${ip}]`), true);
        const url = `https://[${ip}]/repo.git`;
        assert.equal(validateSafeUrl(url).isValid, false);
        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      });
    }
  });

  describe('1.2 Private, Link-Local, and Reserved IP Ranges (RFC 1918, RFC 3927, RFC 6598)', () => {
    const privateTestCases = [
      // 10.0.0.0/8
      { ip: '10.0.0.1', desc: '10.0.0.0/8 start' },
      { ip: '10.254.1.99', desc: '10.0.0.0/8 mid' },
      { ip: '10.255.255.254', desc: '10.0.0.0/8 end' },
      // 172.16.0.0/12
      { ip: '172.16.0.1', desc: '172.16.0.0/12 start' },
      { ip: '172.24.10.5', desc: '172.16.0.0/12 mid' },
      { ip: '172.31.255.254', desc: '172.16.0.0/12 end' },
      // 192.168.0.0/16
      { ip: '192.168.0.1', desc: '192.168.0.0/16 start' },
      { ip: '192.168.1.1', desc: '192.168.0.0/16 common router' },
      { ip: '192.168.255.254', desc: '192.168.0.0/16 end' },
      // 169.254.0.0/16 Link-Local
      { ip: '169.254.0.1', desc: '169.254.0.0/16 start' },
      { ip: '169.254.100.50', desc: '169.254.0.0/16 mid' },
      { ip: '169.254.255.254', desc: '169.254.0.0/16 end' },
      // Carrier-Grade NAT 100.64.0.0/10
      { ip: '100.64.0.1', desc: '100.64.0.0/10 start' },
      { ip: '100.100.50.2', desc: '100.64.0.0/10 mid' },
      { ip: '100.127.255.254', desc: '100.64.0.0/10 end' },
      // TEST-NET & Benchmark ranges
      { ip: '192.0.2.1', desc: 'TEST-NET-1 RFC 5737' },
      { ip: '198.51.100.1', desc: 'TEST-NET-2 RFC 5737' },
      { ip: '203.0.113.1', desc: 'TEST-NET-3 RFC 5737' },
      { ip: '198.18.0.1', desc: 'Benchmark testing RFC 2544' },
      { ip: '198.19.255.254', desc: 'Benchmark testing end' },
      // Multicast and Future Reserved
      { ip: '224.0.0.1', desc: 'Multicast 224.0.0.0/4' },
      { ip: '239.255.255.255', desc: 'Multicast end' },
      { ip: '240.0.0.1', desc: 'Reserved 240.0.0.0/4' },
      { ip: '255.255.255.255', desc: 'Broadcast' }
    ];

    for (const { ip, desc } of privateTestCases) {
      it(`blocks private/reserved IPv4: ${ip} (${desc})`, () => {
        assert.equal(isPrivateOrBlockedIPv4(ip), true, `Must block ${ip}`);
        assert.equal(isPrivateOrBlockedHost(ip), true);

        const url = `https://${ip}/org/repo`;
        assert.equal(validateSafeUrl(url).isValid, false);
        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      });
    }

    const privateIpv6Cases = [
      { ip: 'fe80::1', desc: 'Link-Local fe80::/10' },
      { ip: 'febf:ffff:ffff:ffff::1', desc: 'Link-Local upper bound' },
      { ip: 'fc00::1', desc: 'Unique Local fc00::/7' },
      { ip: 'fd00::1', desc: 'Unique Local fd00::' },
      { ip: 'fd12:3456:789a:1::1', desc: 'Unique Local internal' },
      { ip: '::ffff:192.168.1.1', desc: 'IPv4-mapped private IPv4' },
      { ip: '::ffff:10.0.0.1', desc: 'IPv4-mapped 10.x' },
      { ip: '::ffff:127.0.0.1', desc: 'IPv4-mapped loopback' },
      { ip: '100::1', desc: 'Discard prefix 100::/64' },
      { ip: '64:ff9b::127.0.0.1', desc: 'IPv4/IPv6 translation loopback' }
    ];

    for (const { ip, desc } of privateIpv6Cases) {
      it(`blocks private/reserved IPv6: ${ip} (${desc})`, () => {
        assert.equal(isPrivateOrBlockedIPv6(ip), true, `Must block IPv6 ${ip}`);
        assert.equal(isPrivateOrBlockedHost(`[${ip}]`), true);

        const url = `https://[${ip}]/org/repo`;
        assert.equal(validateSafeUrl(url).isValid, false);
        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      });
    }

    it('permits genuine public IPv4 addresses', () => {
      const publicIps = ['8.8.8.8', '1.1.1.1', '140.82.114.4', '151.101.65.140'];
      for (const ip of publicIps) {
        assert.equal(isPrivateOrBlockedIPv4(ip), false, `Should allow public IP ${ip}`);
        assert.equal(isPrivateOrBlockedHost(ip), false);
      }
    });
  });

  describe('1.3 Cloud Metadata Endpoint Rejection', () => {
    const cloudMetadataEndpoints = [
      // AWS IMDSv1 / IMDSv2
      { url: 'https://169.254.169.254/latest/meta-data/', desc: 'AWS IMDSv1/v2 IPv4' },
      { url: 'https://[fd00:ec2::254]/latest/meta-data/', desc: 'AWS IMDS IPv6' },
      // GCP Metadata
      { url: 'https://metadata.google.internal/computeMetadata/v1/', desc: 'GCP Internal Metadata' },
      { url: 'https://subdomain.metadata.google.internal/', desc: 'GCP Subdomain Metadata' },
      { url: 'https://metadata.internal/meta-data/', desc: 'Generic metadata.internal' },
      // Azure / OpenStack
      { url: 'https://instance-data/latest/meta-data/', desc: 'Azure / OpenStack instance-data' }
    ];

    for (const { url, desc } of cloudMetadataEndpoints) {
      it(`blocks cloud metadata endpoint: ${desc} (${url})`, () => {
        const parsed = new URL(url);
        assert.equal(isPrivateOrBlockedHost(parsed.hostname), true, `Should detect ${parsed.hostname} as metadata`);

        const check = validateSafeUrl(url);
        assert.equal(check.isValid, false);
        assert.ok(check.error.includes('prohibited') || check.error.includes('SSRF'));

        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      });
    }
  });

  describe('1.4 Alternate IP Encodings & Bypass Formats', () => {
    it('blocks decimal integer representation of loopback (2130706433 -> 127.0.0.1)', () => {
      assert.equal(parseNumericIp('2130706433'), '127.0.0.1');
      assert.equal(isPrivateOrBlockedHost('2130706433'), true);

      const url = 'https://2130706433/org/repo';
      assert.equal(validateSafeUrl(url).isValid, false);
      assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
    });

    it('blocks decimal integer representation of AWS metadata (2852039166 -> 169.254.169.254)', () => {
      assert.equal(parseNumericIp('2852039166'), '169.254.169.254');
      assert.equal(isPrivateOrBlockedHost('2852039166'), true);

      const url = 'https://2852039166/latest/meta-data';
      assert.equal(validateSafeUrl(url).isValid, false);
      assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
    });

    it('blocks hexadecimal IP representation (0x7f000001 -> 127.0.0.1)', () => {
      assert.equal(parseNumericIp('0x7f000001'), '127.0.0.1');
      assert.equal(isPrivateOrBlockedHost('0x7f000001'), true);

      const url = 'https://0x7f000001/repo';
      assert.equal(validateSafeUrl(url).isValid, false);
      assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
    });

    it('blocks octal IP representation (0177.0.0.1 -> 127.0.0.1)', () => {
      assert.equal(parseNumericIp('0177.0.0.1'), '127.0.0.1');
      assert.equal(isPrivateOrBlockedHost('0177.0.0.1'), true);

      const url = 'https://0177.0.0.1/repo';
      assert.equal(validateSafeUrl(url).isValid, false);
      assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
    });

    it('blocks public wildcard DNS mapping to loopback or private ranges (nip.io, sslip.io)', () => {
      const wildcardDomains = [
        '127.0.0.1.nip.io',
        '169.254.169.254.nip.io',
        '10.0.0.1.nip.io',
        '192.168.1.1.sslip.io'
      ];

      for (const domain of wildcardDomains) {
        assert.equal(isPrivateOrBlockedHost(domain), true, `Must block wildcard domain ${domain}`);
        const url = `https://${domain}/repo.git`;
        assert.equal(validateSafeUrl(url).isValid, false);
      }
    });
  });

  describe('1.5 URL Protocol, Port, and Credential Validation', () => {
    it('rejects unencrypted HTTP protocol', () => {
      const check = validateSafeUrl('http://github.com/vulnex-org/test-repo');
      assert.equal(check.isValid, false);
      assert.ok(check.error.includes('Only secure HTTPS URLs are allowed'));

      assert.equal(SafeHttpsRepoUrl.safeParse('http://github.com/vulnex-org/test-repo').success, false);
    });

    it('rejects alternative dangerous protocols (ftp, gopher, file, javascript)', () => {
      const schemes = ['ftp', 'gopher', 'file', 'ssh', 'data'];
      for (const scheme of schemes) {
        const url = `${scheme}://github.com/test`;
        const check = validateSafeUrl(url);
        assert.equal(check.isValid, false);
        assert.equal(SafeHttpsRepoUrl.safeParse(url).success, false);
      }
    });

    it('rejects embedded credentials / token injection in repository URL', () => {
      const credentialUrls = [
        'https://admin:password@github.com/org/repo',
        'https://ghp_secrettoken123@github.com/org/repo',
        'https://user:@github.com/org/repo'
      ];

      for (const url of credentialUrls) {
        const check = validateSafeUrl(url);
        assert.equal(check.isValid, false);
        assert.ok(check.error.includes('credentials') || check.error.includes('prohibited'));

        assert.throws(
          () => validateGitHubUrl(url),
          (err) => err.code === 'INVALID_URL' && err.message.includes('credentials')
        );
      }
    });

    it('rejects non-standard ports (e.g. 8080, 22, 8443)', () => {
      const nonStandardUrls = [
        'https://github.com:8080/org/repo',
        'https://github.com:22/org/repo',
        'https://github.com:8443/org/repo'
      ];

      for (const url of nonStandardUrls) {
        const check = validateSafeUrl(url);
        assert.equal(check.isValid, false);
        assert.ok(check.error.includes('Non-standard port'));

        assert.throws(
          () => validateGitHubUrl(url),
          (err) => err.code === 'INVALID_URL' && err.message.includes('port')
        );
      }
    });

    it('accepts valid HTTPS GitHub repository URLs', () => {
      const validUrl = 'https://github.com/vulnex-org/safe-repo';
      const check = validateSafeUrl(validUrl, { allowedHosts: ['github.com'] });
      assert.equal(check.isValid, true);
      assert.equal(SafeHttpsRepoUrl.safeParse(validUrl).success, true);

      const parsedGit = validateGitHubUrl(validUrl);
      assert.equal(parsedGit.isValid, true);
      assert.equal(parsedGit.owner, 'vulnex-org');
      assert.equal(parsedGit.repo, 'safe-repo');
    });
  });

  describe('1.6 DNS Rebinding & Asynchronous Resolution Defense', () => {
    it('blocks hostname that resolves to 127.0.0.1 via mock DNS', async () => {
      const mockDnsLookup = async (host) => {
        return [{ address: '127.0.0.1', family: 4 }];
      };

      const result = await validateUrlAndResolveDns('https://innocent-looking-domain.com/repo', {
        dnsLookup: mockDnsLookup
      });

      assert.equal(result.isValid, false);
      assert.ok(result.error.includes('resolved to prohibited private/local IP'));
      assert.ok(result.error.includes('DNS rebinding'));
    });

    it('blocks hostname that resolves to cloud metadata 169.254.169.254 via DNS', async () => {
      const mockDnsLookup = async (host) => {
        return [{ address: '169.254.169.254', family: 4 }];
      };

      const result = await validateUrlAndResolveDns('https://rebinding-attack.org/exploit', {
        dnsLookup: mockDnsLookup
      });

      assert.equal(result.isValid, false);
      assert.ok(result.error.includes('169.254.169.254'));
    });

    it('blocks multi-A-record response if any resolved IP is in private address space', async () => {
      const mockDnsLookup = async (host) => {
        return [
          { address: '140.82.114.4', family: 4 }, // public github IP
          { address: '10.0.0.5', family: 4 }      // internal private IP
        ];
      };

      const result = await validateUrlAndResolveDns('https://multi-record-target.com/repo', {
        dnsLookup: mockDnsLookup
      });

      assert.equal(result.isValid, false);
      assert.ok(result.error.includes('10.0.0.5'));
    });

    it('permits hostname resolving strictly to public IPs', async () => {
      const mockDnsLookup = async (host) => {
        return [{ address: '140.82.114.3', family: 4 }];
      };

      const result = await validateUrlAndResolveDns('https://github.com/vulnex-org/test-repo', {
        dnsLookup: mockDnsLookup,
        allowedHosts: ['github.com']
      });

      assert.equal(result.isValid, true);
      assert.deepEqual(result.resolvedAddresses, ['140.82.114.3']);
    });
  });

  describe('1.7 HTTP Redirect Chain Validation', () => {
    it('rejects redirect targeting cloud metadata endpoint', async () => {
      const redirect = await validateRedirect(
        'https://github.com/org/repo',
        'https://169.254.169.254/latest/meta-data/'
      );

      assert.equal(redirect.isValid, false);
      assert.ok(redirect.error.includes('Redirect blocked by SSRF policy'));
    });

    it('rejects redirect targeting localhost loopback', async () => {
      const redirect = await validateRedirect(
        'https://github.com/org/repo',
        'https://localhost:443/internal-admin'
      );

      assert.equal(redirect.isValid, false);
      assert.ok(redirect.error.includes('SSRF protection'));
    });

    it('rejects redirect degrading protocol to HTTP', async () => {
      const redirect = await validateRedirect(
        'https://github.com/org/repo',
        'http://github.com/org/repo'
      );

      assert.equal(redirect.isValid, false);
      assert.ok(redirect.error.includes('Only secure HTTPS URLs are allowed'));
    });

    it('accepts valid relative redirect on safe public host', async () => {
      const mockDnsLookup = async () => [{ address: '140.82.114.3', family: 4 }];
      const redirect = await validateRedirect(
        'https://github.com/org/old-repo',
        '/org/new-repo',
        { dnsLookup: mockDnsLookup, allowedHosts: ['github.com'] }
      );

      assert.equal(redirect.isValid, true);
      assert.equal(redirect.targetUrl, 'https://github.com/org/new-repo');
    });
  });
});

// ----------------------------------------------------------------------------
// 2. ZIP Slip & Archive Security Tests
// ----------------------------------------------------------------------------
describe('2. ZIP Slip & Archive Security', () => {
  let tempDestDir;

  beforeEach(() => {
    tempDestDir = createIsolatedTempDir('vulnex-zip-slip-test-');
  });

  afterEach(() => {
    if (tempDestDir && fs.existsSync(tempDestDir)) {
      fs.rmSync(tempDestDir, { recursive: true, force: true });
    }
  });

  describe('2.1 Directory Traversal Entry Rejection', () => {
    it('rejects simple "../" directory traversal in ZIP entry name', () => {
      const zip = new AdmZip();
      zip.addFile('valid.txt', Buffer.from('ok'));
      const entry = zip.getEntry('valid.txt');
      entry.entryName = '../evil.sh';
      const buffer = zip.toBuffer();

      assert.throws(
        () => validateZipArchive(buffer),
        (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('traversal')
      );

      assert.throws(
        () => extractZipArchive(buffer, tempDestDir),
        (err) => err.code === 'UNSUPPORTED_ARCHIVE'
      );
    });

    it('rejects deep nested directory traversal ("dir1/dir2/../../../evil.sh")', () => {
      const zip = new AdmZip();
      zip.addFile('valid.txt', Buffer.from('payload'));
      const entry = zip.getEntry('valid.txt');
      entry.entryName = 'src/components/../../../etc/cron.d/evil';
      const buffer = zip.toBuffer();

      assert.throws(
        () => validateZipArchive(buffer),
        (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('traversal')
      );
    });

    it('rejects Windows backslash directory traversal ("..\\evil.bat" and "dir\\..\\..\\evil.bat")', () => {
      const backslashCases = [
        '..\\evil.bat',
        'sub\\..\\..\\evil.bat',
        'a\\b\\c\\..\\..\\..\\..\\evil.exe'
      ];

      for (const entryName of backslashCases) {
        const zip = new AdmZip();
        zip.addFile('test.txt', Buffer.from('bad'));
        const entry = zip.getEntry('test.txt');
        entry.entryName = entryName;
        const buffer = zip.toBuffer();

        assert.throws(
          () => validateZipArchive(buffer),
          (err) => err.code === 'UNSUPPORTED_ARCHIVE'
        );
      }
    });
  });

  describe('2.2 Percent-Encoded Traversal in Archive Entries', () => {
    const encodedTraversalCases = [
      '%2e%2e/evil.sh',
      '%2e%2e%2fevil.sh',
      'subfolder/%2e%2e/file.js',
      'subfolder/%2e%2e%2fescaped.js',
      '%252e%252e/double-encoded.sh'
    ];

    for (const name of encodedTraversalCases) {
      it(`rejects percent-encoded traversal entry: "${name}"`, () => {
        const zip = new AdmZip();
        zip.addFile('placeholder.txt', Buffer.from('malicious payload'));
        const entry = zip.getEntry('placeholder.txt');
        entry.entryName = name;
        const buffer = zip.toBuffer();

        assert.throws(
          () => validateZipArchive(buffer),
          (err) => err.code === 'UNSUPPORTED_ARCHIVE'
        );
      });
    }
  });

  describe('2.3 Absolute Path Entry Rejection', () => {
    const absolutePathCases = [
      '/etc/passwd',
      '/root/.ssh/id_rsa',
      '/var/run/docker.sock',
      'C:\\Windows\\System32\\cmd.exe',
      'C:/Windows/win.ini',
      'D:\\app\\secret.key',
      '\\\\attacker-server\\share\\evil.exe'
    ];

    for (const absPath of absolutePathCases) {
      it(`rejects absolute path entry: "${absPath}"`, () => {
        const zip = new AdmZip();
        zip.addFile('dummy.txt', Buffer.from('data'));
        const entry = zip.getEntry('dummy.txt');
        entry.entryName = absPath;
        const buffer = zip.toBuffer();

        assert.throws(
          () => validateZipArchive(buffer),
          (err) => err.code === 'UNSUPPORTED_ARCHIVE' && (err.message.includes('absolute') || err.message.includes('boundary') || err.message.includes('traversal'))
        );
      });
    }
  });

  describe('2.4 Symbolic Link & Extraction Escape Defenses', () => {
    it('rejects archive entry with S_IFLNK unix symbolic link attribute', () => {
      const zip = new AdmZip();
      zip.addFile('link.txt', Buffer.from('/etc/passwd'));
      const entry = zip.getEntry('link.txt');
      // Set Unix S_IFLNK (0o120777)
      entry.attr = ((0o120777 << 16) >>> 0);
      const buffer = zip.toBuffer();

      assert.throws(
        () => validateZipArchive(buffer),
        (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('symbolic link')
      );
    });

    it('rejects extraction if destination subfolder resolves outside via pre-existing symlink', (t) => {
      const outsideDir = createIsolatedTempDir('vulnex-outside-');
      try {
        const symlinkPath = path.join(tempDestDir, 'symlink_dir');
        try {
          fs.symlinkSync(outsideDir, symlinkPath, 'dir');
        } catch (e) {
          if (t && t.skip) t.skip('Symlinks not supported on host');
          return;
        }

        const zip = new AdmZip();
        zip.addFile('symlink_dir/pwned.txt', Buffer.from('escape payload'));
        const buffer = zip.toBuffer();

        assert.throws(
          () => extractZipArchive(buffer, tempDestDir),
          (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('violation')
        );

        // Verify the file was not written outside
        assert.equal(fs.existsSync(path.join(outsideDir, 'pwned.txt')), false);
      } finally {
        fs.rmSync(outsideDir, { recursive: true, force: true });
      }
    });
  });

  describe('2.5 Zip Bombs & Resource Limits', () => {
    it('rejects archive entry containing prohibited null byte', () => {
      const zip = new AdmZip();
      zip.addFile('normal.txt', Buffer.from('content'));
      const entry = zip.getEntry('normal.txt');
      entry.entryName = 'payload.txt\0.js';
      const buffer = zip.toBuffer();

      assert.throws(
        () => validateZipArchive(buffer),
        (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('null byte')
      );
    });

    it('rejects single file exceeding maximum file bytes threshold', () => {
      const zip = new AdmZip();
      // Add small file but enforce tiny limit in options
      zip.addFile('big.txt', Buffer.alloc(5000, 'A'));
      const buffer = zip.toBuffer();

      assert.throws(
        () => validateZipArchive(buffer, { maxUncompressedBytes: 2000 }),
        (err) => err.code === 'RESOURCE_LIMIT_EXCEEDED'
      );
    });

    it('rejects archive exceeding maximum entry count', () => {
      const zip = new AdmZip();
      for (let i = 0; i < 5; i++) {
        zip.addFile(`file_${i}.txt`, Buffer.from('hello'));
      }
      const buffer = zip.toBuffer();

      assert.throws(
        () => validateZipArchive(buffer, { maxEntries: 3 }),
        (err) => err.code === 'RESOURCE_LIMIT_EXCEEDED' && err.message.includes('entries')
      );
    });
  });
});

// ----------------------------------------------------------------------------
// 3. Path Traversal & Workspace Confinement Tests
// ----------------------------------------------------------------------------
describe('3. Path Traversal & Workspace Confinement', () => {
  let hasSymlink = false;
  let tempWorkspace;
  let outsideDir;
  let sensitiveFileOutside;

  before(() => {
    tempWorkspace = createIsolatedTempDir('vulnex-workspace-test-');
    outsideDir = createIsolatedTempDir('vulnex-outside-test-');

    // Create a sensitive file outside workspace
    sensitiveFileOutside = path.join(outsideDir, 'super-secret.env');
    fs.writeFileSync(sensitiveFileOutside, 'DATABASE_PASSWORD=CRITICAL_LEAK_12345\n');

    // Populate workspace
    fs.mkdirSync(path.join(tempWorkspace, 'src', 'controllers'), { recursive: true });
    fs.writeFileSync(
      path.join(tempWorkspace, 'src', 'controllers', 'auth.js'),
      '// Auth controller\nfunction login() { return true; }\nmodule.exports = login;\n'
    );
    fs.writeFileSync(path.join(tempWorkspace, 'package.json'), JSON.stringify({ name: 'app' }));

    // Create a symlink INSIDE workspace pointing to file OUTSIDE workspace
    const symlinkTarget = path.join(tempWorkspace, 'src', 'symlinked_secret.env');
    try { fs.symlinkSync(sensitiveFileOutside, symlinkTarget); hasSymlink = true; } catch (e) { /* Windows unprivileged symlink skip */ }
  });

  after(() => {
    if (tempWorkspace && fs.existsSync(tempWorkspace)) {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    }
    if (outsideDir && fs.existsSync(outsideDir)) {
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  describe('3.1 SafeRelativeFilePath Schema Traversal Protection', () => {
    const traversalPayloads = [
      '../secret.env',
      '../../etc/passwd',
      'src/../../outside.txt',
      'src/controllers/../../../root.key',
      '/etc/shadow',
      '\\Windows\\win.ini',
      'C:\\autoexec.bat',
      'D:/secret.txt',
      'file.txt\0.js',
      '%2e%2e/evil.sh',
      '%2e%2e%2fevil.sh',
      '%252e%252e/double-encoded.sh'
    ];

    for (const payload of traversalPayloads) {
      it(`rejects traversal path pattern: "${payload}"`, () => {
        const result = SafeRelativeFilePath.safeParse(payload);
        assert.equal(result.success, false, `Expected failure for "${payload}"`);
      });
    }

    it('accepts legitimate canonical relative paths', () => {
      const legitimatePaths = [
        'src/controllers/auth.js',
        'package.json',
        'README.md',
        'lib/utils/db.ts'
      ];

      for (const p of legitimatePaths) {
        const result = SafeRelativeFilePath.safeParse(p);
        assert.equal(result.success, true, `Expected success for "${p}"`);
      }
    });
  });

  describe('3.2 Inventory Service (getFileExcerpt) Workspace Confinement', () => {
    it('rejects relative path traversal attempting to escape workspace', () => {
      assert.throws(
        () => getFileExcerpt(tempWorkspace, '../../outside.txt', 1, 5),
        (err) => err.message.includes('traversal') || err.message.includes('Invalid file path')
      );
    });

    it('rejects absolute paths attempting to access host filesystem', () => {
      assert.throws(
        () => getFileExcerpt(tempWorkspace, '/etc/passwd', 1, 5),
        (err) => err.message.includes('relative') || err.message.includes('Invalid file path')
      );
    });

    it('rejects reading files outside workspace via symbolic link escape', (t) => {
      if (!hasSymlink) { if (t && t.skip) t.skip('Symlinks not supported on host'); return; }
      assert.throws(
        () => getFileExcerpt(tempWorkspace, 'src/symlinked_secret.env', 1, 5),
        (err) => err.message.includes('symbolic link') || err.message.includes('Access denied')
      );
    });

    it('successfully extracts excerpts from legitimate in-workspace files', () => {
      const excerpt = getFileExcerpt(tempWorkspace, 'src/controllers/auth.js', 1, 3);
      assert.equal(excerpt.filePath, 'src/controllers/auth.js');
      assert.ok(excerpt.lines.length >= 2);
      assert.ok(excerpt.rawExcerpt.includes('function login'));
    });
  });

  describe('3.3 Diff Validator Workspace Confinement & Path Verification', () => {
    it('rejects diff file path containing "../" directory traversal', () => {
      const result = validateWorkspacePath('../outside.js', tempWorkspace);
      assert.equal(result.valid, false);
      assert.equal(result.code, 'PATH_TRAVERSAL');
    });

    it('rejects diff file path containing percent-encoded traversal ("%2e%2e")', () => {
      const result = validateWorkspacePath('%2e%2e/escaped.js', tempWorkspace);
      assert.equal(result.valid, false);
      assert.equal(result.code, 'PATH_TRAVERSAL');
    });

    it('rejects diff file path with absolute path or home directory prefix', () => {
      assert.equal(validateWorkspacePath('/etc/passwd', tempWorkspace).valid, false);
      assert.equal(validateWorkspacePath('~/secret.txt', tempWorkspace).valid, false);
      assert.equal(validateWorkspacePath('$HOME/secret.txt', tempWorkspace).valid, false);
    });

    it('rejects diff targeting a symlink pointing outside the workspace', (t) => {
      if (!hasSymlink) { if (t && t.skip) t.skip('Symlinks not supported on host'); return; }
      const result = validateWorkspacePath('src/symlinked_secret.env', tempWorkspace);
      assert.equal(result.valid, false);
      assert.equal(result.code, 'SYMLINK_WORKSPACE_ESCAPE');
    });

    it('rejects patch diff modifying files outside the repository boundary', () => {
      const maliciousDiff = [
        '--- a/../../etc/passwd',
        '+++ b/../../etc/passwd',
        '@@ -1,1 +1,1 @@',
        '-root:x:0:0::/root:/bin/bash',
        '+root:x:0:0::/root:/bin/sh'
      ].join('\n');

      const validation = validateDiffAndPaths(maliciousDiff, tempWorkspace);
      assert.equal(validation.valid, false);
      assert.ok(validation.errors && validation.errors.some(e => e.includes('traversal') || e.includes('escape') || e.includes('outside')));
    });

    it('accepts legitimate unified diff modifying valid repository file', () => {
      const legitimateDiff = [
        '--- a/src/controllers/auth.js',
        '+++ b/src/controllers/auth.js',
        '@@ -1,3 +1,3 @@',
        ' // Auth controller',
        '-function login() { return true; }',
        '+function login() { return Boolean(true); }',
        ' module.exports = login;'
      ].join('\n');

      const validation = validateDiffAndPaths(legitimateDiff, tempWorkspace, {
        findingFilePath: 'src/controllers/auth.js',
        declaredChangedFiles: ['src/controllers/auth.js']
      });

      assert.equal(validation.valid, true);
      assert.deepEqual(validation.changedFiles, ['src/controllers/auth.js']);
    });
  });
});
