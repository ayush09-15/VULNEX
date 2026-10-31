const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const config = require('../config/env');

// Canonical safety limits
const DEFAULT_MAX_ENTRIES = 5000;
const DEFAULT_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024; // 100 MB max uncompressed
const DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024; // 25 MB max per single file

// Unix file type bitmask for symbolic links (S_IFLNK = 0120000)
const S_IFLNK = 0o120000;

/**
 * Validates a ZIP archive buffer or file against ZIP Slip, Zip Bombs,
 * and unsafe symlinks without extracting.
 * 
 * @param {Buffer|string} zipInput - Buffer or file path to ZIP archive
 * @param {Object} [options]
 * @param {number} [options.maxArchiveBytes]
 * @param {number} [options.maxEntries]
 * @param {number} [options.maxUncompressedBytes]
 * @returns {{ isValid: boolean, entryCount: number, totalUncompressedBytes: number, manifest: Array<string> }}
 */
function validateZipArchive(zipInput, options = {}) {
  const maxArchiveBytes = options.maxArchiveBytes || (config.maxUploadMb * 1024 * 1024);
  const maxEntries = options.maxEntries || DEFAULT_MAX_ENTRIES;
  const maxUncompressedBytes = options.maxUncompressedBytes || DEFAULT_MAX_UNCOMPRESSED_BYTES;

  let zip;
  let archiveSizeBytes = 0;

  if (Buffer.isBuffer(zipInput)) {
    archiveSizeBytes = zipInput.length;
    if (archiveSizeBytes > maxArchiveBytes) {
      const err = new Error(`Archive size exceeds the maximum permitted limit of ${config.maxUploadMb} MB.`);
      err.code = 'FILE_TOO_LARGE';
      throw err;
    }
    try {
      zip = new AdmZip(zipInput);
    } catch {
      const err = new Error('Corrupted or invalid ZIP archive file.');
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }
  } else if (typeof zipInput === 'string') {
    if (!fs.existsSync(zipInput)) {
      const err = new Error(`ZIP file not found at path: ${zipInput}`);
      err.code = 'RESOURCE_NOT_FOUND';
      throw err;
    }
    const stat = fs.statSync(zipInput);
    archiveSizeBytes = stat.size;
    if (archiveSizeBytes > maxArchiveBytes) {
      const err = new Error(`Archive size exceeds the maximum permitted limit of ${config.maxUploadMb} MB.`);
      err.code = 'FILE_TOO_LARGE';
      throw err;
    }
    try {
      zip = new AdmZip(zipInput);
    } catch {
      const err = new Error('Corrupted or invalid ZIP archive file.');
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }
  } else {
    const err = new Error('Invalid input: ZIP archive must be a Buffer or file path string.');
    err.code = 'INVALID_INPUT';
    throw err;
  }

  const entries = zip.getEntries();
  if (!entries || entries.length === 0) {
    const err = new Error('ZIP archive is empty.');
    err.code = 'UNSUPPORTED_ARCHIVE';
    throw err;
  }

  if (entries.length > maxEntries) {
    const err = new Error(`Archive contains ${entries.length} entries, exceeding the safe limit of ${maxEntries}.`);
    err.code = 'RESOURCE_LIMIT_EXCEEDED';
    throw err;
  }

  let totalUncompressed = 0;
  const manifest = [];

  for (const entry of entries) {
    const rawName = entry.entryName;

    // 1. Check for null bytes or illegal characters
    if (rawName.includes('\0')) {
      const err = new Error('Archive entry contains illegal null byte.');
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    // 2. Reject absolute paths or Windows drive letters
    if (path.isAbsolute(rawName) || /^[A-Za-z]:[\\/]/.test(rawName) || rawName.startsWith('/') || rawName.startsWith('\\')) {
      const err = new Error(`Archive contains illegal absolute path entry: "${rawName}".`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    // 2b. Check decoded path for traversal or escapes
    let decodedName = rawName;
    try {
      while (decodedName.includes('%')) {
        const next = decodeURIComponent(decodedName);
        if (next === decodedName) break;
        decodedName = next;
      }
    } catch {
      const err = new Error(`Archive entry contains malformed percent encoding: "${rawName}".`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    if (decodedName.includes('\0')) {
      const err = new Error('Archive entry contains illegal null byte.');
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    if (path.isAbsolute(decodedName) || /^[A-Za-z]:[\\/]/.test(decodedName) || decodedName.startsWith('/') || decodedName.startsWith('\\')) {
      const err = new Error(`Archive contains illegal absolute path entry: "${rawName}".`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    const decodedParts = decodedName.split(/[/\\]/);
    if (decodedParts.includes('..') || decodedParts.some((p) => p === '..' || /^\.\.[/\\]/.test(p))) {
      const err = new Error(`Archive entry "${rawName}" contains directory traversal sequence (".."). Access blocked.`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    // 3. ZIP Slip Directory Traversal Guard (no ".." segments or boundary escapes)
    const normalizedParts = rawName.split(/[/\\]/);
    if (normalizedParts.includes('..')) {
      const err = new Error(`Archive entry "${rawName}" contains directory traversal sequence (".."). Access blocked.`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    const normalizedPath = path.normalize(rawName);
    if (normalizedPath.startsWith('..') || path.isAbsolute(normalizedPath)) {
      const err = new Error(`Archive entry "${rawName}" escapes extraction boundary.`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    // 4. Reject Symbolic Links (prevent arbitrary file disclosure / symlink traversal)
    // In ZIP specification, unix file mode attributes reside in higher 16 bits of entry.attr
    const unixMode = (entry.attr >>> 16) & 0o170000;
    if (unixMode === S_IFLNK) {
      const err = new Error(`Archive entry "${rawName}" is a symbolic link. Symlinks in untrusted archives are prohibited.`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    // 5. Size caps & Zip Bomb protection
    const uncompressedSize = entry.header.size || 0;
    if (uncompressedSize > DEFAULT_MAX_FILE_BYTES) {
      const err = new Error(`Single file entry "${rawName}" (${uncompressedSize} bytes) exceeds the 25 MB limit.`);
      err.code = 'RESOURCE_LIMIT_EXCEEDED';
      throw err;
    }

    totalUncompressed += uncompressedSize;
    if (totalUncompressed > maxUncompressedBytes) {
      const err = new Error(`Total uncompressed archive contents (${totalUncompressed} bytes) exceed safe limit of 100 MB (Zip Bomb protection).`);
      err.code = 'RESOURCE_LIMIT_EXCEEDED';
      throw err;
    }

    manifest.push(rawName);
  }

  return {
    isValid: true,
    entryCount: entries.length,
    totalUncompressedBytes: totalUncompressed,
    manifest
  };
}

/**
 * Safely extracts a validated ZIP archive into an isolated destination directory.
 * Guarantees that every extracted file resides strictly within the destination root.
 * 
 * @param {Buffer|string} zipInput - Buffer or file path to ZIP archive
 * @param {string} destinationDir - Absolute path to extraction root
 * @param {Object} [options]
 * @returns {{ extractedCount: number, targetDir: string, totalBytes: number }}
 */
function extractZipArchive(zipInput, destinationDir, options = {}) {
  // First, run comprehensive security validation
  validateZipArchive(zipInput, options);

  const resolvedDest = path.resolve(destinationDir);
  fs.mkdirSync(resolvedDest, { recursive: true });
  const realDest = fs.realpathSync(resolvedDest);
  const realDestPrefix = realDest.endsWith(path.sep) ? realDest : realDest + path.sep;

  const zip = Buffer.isBuffer(zipInput) ? new AdmZip(zipInput) : new AdmZip(zipInput);
  const entries = zip.getEntries();
  let extractedCount = 0;
  let totalBytes = 0;

  for (const entry of entries) {
    const entryName = entry.entryName;
    const targetPath = path.resolve(resolvedDest, entryName);

    // Double-check path containment invariant
    if (!targetPath.startsWith(resolvedDest + path.sep) && targetPath !== resolvedDest) {
      const err = new Error(`Path containment violation for entry: "${entryName}".`);
      err.code = 'UNSUPPORTED_ARCHIVE';
      throw err;
    }

    if (entry.isDirectory) {
      fs.mkdirSync(targetPath, { recursive: true });
      const realTargetDir = fs.realpathSync(targetPath);
      if (!realTargetDir.startsWith(realDestPrefix) && realTargetDir !== realDest) {
        const err = new Error(`Path containment violation for directory: "${entryName}" via symlink.`);
        err.code = 'UNSUPPORTED_ARCHIVE';
        throw err;
      }
    } else {
      const parentDir = path.dirname(targetPath);
      fs.mkdirSync(parentDir, { recursive: true });

      const realParent = fs.realpathSync(parentDir);
      if (!realParent.startsWith(realDestPrefix) && realParent !== realDest) {
        const err = new Error(`Path containment violation for entry: "${entryName}" via symlink.`);
        err.code = 'UNSUPPORTED_ARCHIVE';
        throw err;
      }

      if (fs.existsSync(targetPath)) {
        const realTarget = fs.realpathSync(targetPath);
        if (!realTarget.startsWith(realDestPrefix) && realTarget !== realDest) {
          const err = new Error(`Path containment violation for entry: "${entryName}" via pre-existing symlink.`);
          err.code = 'UNSUPPORTED_ARCHIVE';
          throw err;
        }
      }

      const content = entry.getData();
      fs.writeFileSync(targetPath, content);
      extractedCount++;
      totalBytes += content.length;
    }
  }

  return {
    extractedCount,
    targetDir: resolvedDest,
    totalBytes
  };
}

function ingestZipArchive(zipBuffer, options = {}) {
  const repositoryService = require('./repository.service');
  return repositoryService.ingestZipArchive(zipBuffer, options);
}

module.exports = {
  validateZipArchive,
  extractZipArchive,
  ingestZipArchive,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_MAX_UNCOMPRESSED_BYTES,
  DEFAULT_MAX_FILE_BYTES
};
