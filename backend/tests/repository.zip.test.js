const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const { validateZipArchive, extractZipArchive } = require('../src/services/zip.service');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'vulnex-zip-test-'));
}

describe('Bounded ZIP Validation & Extraction (Commit 11)', () => {
  it('safely validates and extracts a legitimate ZIP archive into isolated directory', () => {
    const zip = new AdmZip();
    zip.addFile('package.json', Buffer.from(JSON.stringify({ name: 'test-app', version: '1.0.0' })));
    zip.addFile('src/index.js', Buffer.from('console.log("hello vulnex");\n'));
    zip.addFile('src/utils/math.js', Buffer.from('module.exports = { add: (a, b) => a + b };\n'));
    const zipBuffer = zip.toBuffer();

    const tempDir = createTempDir();
    try {
      const validation = validateZipArchive(zipBuffer);
      assert.equal(validation.isValid, true);
      assert.equal(validation.entryCount, 3);
      assert.ok(validation.manifest.includes('src/index.js'));

      const result = extractZipArchive(zipBuffer, tempDir);
      assert.equal(result.extractedCount, 3);
      assert.ok(fs.existsSync(path.join(tempDir, 'package.json')));
      assert.ok(fs.existsSync(path.join(tempDir, 'src/index.js')));
      assert.ok(fs.existsSync(path.join(tempDir, 'src/utils/math.js')));
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('rejects ZIP Slip path traversal sequences ("../")', () => {
    const zip = new AdmZip();
    zip.addFile('placeholder.js', Buffer.from('malicious payload'));
    const entry = zip.getEntry('placeholder.js');
    entry.entryName = '../evil.js';
    const zipBuffer = zip.toBuffer();

    assert.throws(
      () => validateZipArchive(zipBuffer),
      (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('traversal sequence')
    );
  });

  it('rejects nested ZIP Slip traversal sequences ("foo/../../bar.js")', () => {
    const zip = new AdmZip();
    zip.addFile('placeholder.js', Buffer.from('malicious payload'));
    const entry = zip.getEntry('placeholder.js');
    entry.entryName = 'subfolder/../../escaped.js';
    const zipBuffer = zip.toBuffer();

    assert.throws(
      () => validateZipArchive(zipBuffer),
      (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('traversal sequence')
    );
  });

  it('rejects absolute paths or Windows drive letters in entry names', () => {
    const zip = new AdmZip();
    zip.addFile('placeholder.js', Buffer.from('root:x:0:0'));
    const entry = zip.getEntry('placeholder.js');
    entry.entryName = '/etc/shadow';
    const zipBuffer = zip.toBuffer();

    assert.throws(
      () => validateZipArchive(zipBuffer),
      (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('absolute path')
    );
  });

  it('rejects symbolic link entries to protect against host filesystem traversal', () => {
    const zip = new AdmZip();
    zip.addFile('link.js', Buffer.from('/etc/passwd'));
    const entry = zip.getEntry('link.js');
    // Set Unix S_IFLNK (0o120777) in higher 16 bits as unsigned 32-bit int
    entry.attr = ((0o120777 << 16) >>> 0);
    const zipBuffer = zip.toBuffer();

    assert.throws(
      () => validateZipArchive(zipBuffer),
      (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('symbolic link')
    );
  });

  it('rejects archives exceeding maximum compressed archive size limit', () => {
    const zip = new AdmZip();
    zip.addFile('random.bin', crypto.randomBytes(2000));
    const zipBuffer = zip.toBuffer();

    // Set max limit to 500 bytes to simulate limit enforcement
    assert.throws(
      () => validateZipArchive(zipBuffer, { maxArchiveBytes: 500 }),
      (err) => err.code === 'FILE_TOO_LARGE'
    );
  });

  it('rejects Zip Bombs exceeding maximum uncompressed size limits', () => {
    const zip = new AdmZip();
    // High-compression repeating zeroes (zip bomb pattern)
    zip.addFile('bomb.dat', Buffer.alloc(10 * 1024 * 1024, 0));
    const zipBuffer = zip.toBuffer();

    // Set max uncompressed limit to 5 MB
    assert.throws(
      () => validateZipArchive(zipBuffer, { maxUncompressedBytes: 5 * 1024 * 1024 }),
      (err) => err.code === 'RESOURCE_LIMIT_EXCEEDED' && err.message.includes('Zip Bomb')
    );
  });

  it('rejects corrupted or non-zip buffers', () => {
    const junkBuffer = Buffer.from('This is not a zip file header');
    assert.throws(
      () => validateZipArchive(junkBuffer),
      (err) => err.code === 'UNSUPPORTED_ARCHIVE'
    );
  });

  it('rejects empty ZIP archives', () => {
    const zip = new AdmZip();
    const emptyBuffer = zip.toBuffer();
    assert.throws(
      () => validateZipArchive(emptyBuffer),
      (err) => err.code === 'UNSUPPORTED_ARCHIVE' && err.message.includes('empty')
    );
  });
});
