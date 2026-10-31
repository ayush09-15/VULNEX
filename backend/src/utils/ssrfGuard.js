/**
 * VULNEX SSRF Guard & Safe URL Resolution Utility
 *
 * Implements:
 * - Comprehensive detection of loopback, private, link-local, carrier-grade NAT, and reserved IP ranges.
 * - Cloud metadata endpoint blocking (AWS IMDSv1/v2, GCP, Azure, OpenStack).
 * - Multi-format IP parsing (dotted-quad, integer/decimal, hex, octal, IPv4-mapped IPv6).
 * - DNS rebinding defense via asynchronous DNS resolution and address validation.
 * - Safe redirect inspection ensuring redirect chains cannot target prohibited destinations.
 */

const dns = require('dns');
const { URL } = require('url');

/**
 * Checks whether an IPv4 address string is in a private, loopback, link-local,
 * or reserved range according to RFC 1918, RFC 3927, RFC 5735, RFC 1122.
 *
 * @param {string} ip - IPv4 address string (e.g. '127.0.0.1')
 * @returns {boolean}
 */
function isPrivateOrBlockedIPv4(ip) {
  if (typeof ip !== 'string') return true;
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }
  const [b0, b1, b2, b3] = parts;

  // 0.0.0.0/8 (Current network / "this" host)
  if (b0 === 0) return true;

  // 10.0.0.0/8 (Private-Use RFC 1918)
  if (b0 === 10) return true;

  // 100.64.0.0/10 (Shared Address Space / Carrier-Grade NAT RFC 6598)
  if (b0 === 100 && (b1 >= 64 && b1 <= 127)) return true;

  // 127.0.0.0/8 (Loopback RFC 1122)
  if (b0 === 127) return true;

  // 169.254.0.0/16 (Link Local / Cloud Metadata RFC 3927)
  if (b0 === 169 && b1 === 254) return true;

  // 172.16.0.0/12 (Private-Use RFC 1918)
  if (b0 === 172 && (b1 >= 16 && b1 <= 31)) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments RFC 6890)
  if (b0 === 192 && b1 === 0 && b2 === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1 RFC 5737)
  if (b0 === 192 && b1 === 0 && b2 === 2) return true;

  // 192.168.0.0/16 (Private-Use RFC 1918)
  if (b0 === 192 && b1 === 168) return true;

  // 198.18.0.0/15 (Benchmark Testing RFC 2544)
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2 RFC 5737)
  if (b0 === 198 && b1 === 51 && b2 === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3 RFC 5737)
  if (b0 === 203 && b1 === 0 && b2 === 113) return true;

  // 224.0.0.0/4 (Multicast RFC 5771)
  if (b0 >= 224 && b0 <= 239) return true;

  // 240.0.0.0/4 (Reserved for Future Use RFC 1112)
  if (b0 >= 240) return true;

  // 255.255.255.255 (Limited Broadcast)
  if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) return true;

  return false;
}

/**
 * Extracts dotted-quad IPv4 from an IPv6 suffix (e.g. ::ffff:192.168.1.1 or ::ffff:c0a8:101).
 *
 * @param {string} clean - Normalized IPv6 address without brackets
 * @returns {string|null}
 */
function extractIPv4FromIPv6Suffix(clean) {
  const lastPart = clean.split(':').pop();
  if (lastPart && lastPart.includes('.')) {
    return lastPart;
  }
  const parts = clean.split(':');
  if (parts.length >= 2) {
    const h1 = parts[parts.length - 2];
    const h2 = parts[parts.length - 1];
    if (/^[0-9a-f]{1,4}$/i.test(h1) && /^[0-9a-f]{1,4}$/i.test(h2)) {
      const n1 = parseInt(h1, 16);
      const n2 = parseInt(h2, 16);
      return `${(n1 >>> 8) & 255}.${n1 & 255}.${(n2 >>> 8) & 255}.${n2 & 255}`;
    }
  }
  return null;
}

/**
 * Checks whether an IPv6 address string is private, loopback, link-local,
 * unique-local, or IPv4-mapped private.
 *
 * @param {string} ip - IPv6 address string
 * @returns {boolean}
 */
function isPrivateOrBlockedIPv6(ip) {
  if (typeof ip !== 'string') return true;
  let clean = ip.toLowerCase().replace(/^\[|\]$/g, '');

  // Loopback ::1
  if (clean === '::1' || clean === '0:0:0:0:0:0:0:1' || /^0*(?::0*)*:1$/.test(clean)) return true;

  // Unspecified ::
  if (clean === '::' || clean === '0:0:0:0:0:0:0:0' || /^0*(?::0*)*$/.test(clean)) return true;

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1 / ::ffff:c0a8:101)
  if (clean.startsWith('::ffff:') || clean.startsWith('0:0:0:0:0:ffff:')) {
    const v4 = extractIPv4FromIPv6Suffix(clean);
    if (v4) return isPrivateOrBlockedIPv4(v4);
  }

  // Link-local: fe80::/10 (fe80: to febf:)
  if (/^fe[89ab][0-9a-f]?:/i.test(clean)) return true;

  // Unique local: fc00::/7 (fc00: to fdff:) - covers AWS IPv6 IMDS [fd00:ec2::254]
  if (/^f[cd][0-9a-f]{2}:/i.test(clean) || clean.startsWith('fd00:')) return true;

  // Discard prefix 100::/64
  if (clean.startsWith('100::')) return true;

  // IPv4/IPv6 translation 64:ff9b::/96
  if (clean.startsWith('64:ff9b::')) {
    const v4 = extractIPv4FromIPv6Suffix(clean);
    if (v4) return isPrivateOrBlockedIPv4(v4);
  }

  return false;
}

/**
 * Parses integer, octal, or hex representations of IP addresses.
 * E.g., '2130706433' -> '127.0.0.1', '0177.0.0.1' -> '127.0.0.1'
 *
 * @param {string} host
 * @returns {string|null} Dotted quad string or null
 */
function parseNumericIp(host) {
  if (typeof host !== 'string') return null;

  // Pure decimal integer IP e.g. 2130706433 (127.0.0.1) or 2852039166 (169.254.169.254)
  if (/^\d{8,11}$/.test(host)) {
    const num = parseInt(host, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const b0 = (num >>> 24) & 255;
      const b1 = (num >>> 16) & 255;
      const b2 = (num >>> 8) & 255;
      const b3 = num & 255;
      return `${b0}.${b1}.${b2}.${b3}`;
    }
  }

  // Hexadecimal IP e.g. 0x7f000001
  if (/^0x[0-9a-f]{1,8}$/i.test(host)) {
    const num = parseInt(host, 16);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const b0 = (num >>> 24) & 255;
      const b1 = (num >>> 16) & 255;
      const b2 = (num >>> 8) & 255;
      const b3 = num & 255;
      return `${b0}.${b1}.${b2}.${b3}`;
    }
  }

  // Octal/mixed parts e.g. 0177.0.0.1
  if (/^0[0-7]+(?:\.[0-9]+){3}$/.test(host)) {
    const parts = host.split('.').map(p => p.startsWith('0') && p.length > 1 ? parseInt(p, 8) : parseInt(p, 10));
    return parts.join('.');
  }

  return null;
}

/**
 * Cloud metadata hostnames across major providers
 */
const CLOUD_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.internal',
  'instance-data',
  '[fd00:ec2::254]',
  'fd00:ec2::254'
]);

/**
 * Checks if a hostname or IP is private, loopback, link-local, cloud metadata, or reserved.
 *
 * @param {string} rawHost
 * @returns {boolean}
 */
function isPrivateOrBlockedHost(rawHost) {
  if (!rawHost || typeof rawHost !== 'string') return true;

  const host = rawHost.trim().toLowerCase();

  // Exact known loopback or metadata hostnames
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (CLOUD_METADATA_HOSTS.has(host) || CLOUD_METADATA_HOSTS.has(host.replace(/^\[|\]$/g, ''))) return true;
  if (host.endsWith('.metadata.google.internal')) return true;

  // Numeric (decimal / hex / octal) IP check
  const numericParsed = parseNumericIp(host);
  if (numericParsed) {
    if (isPrivateOrBlockedIPv4(numericParsed)) return true;
  }

  // Direct IPv4 check
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    return isPrivateOrBlockedIPv4(host);
  }

  // IPv6 check
  if (host.includes(':')) {
    return isPrivateOrBlockedIPv6(host);
  }

  // Wildcard DNS services mapping to private IPs (nip.io, xip.io, sslip.io)
  const nipMatch = host.match(/((?:\d{1,3}\.){3}\d{1,3})\.(?:nip|xip|sslip)\.io$/);
  if (nipMatch && nipMatch[1]) {
    if (isPrivateOrBlockedIPv4(nipMatch[1])) return true;
  }

  return false;
}

/**
 * Synchronously validates URL syntax and static hostname safety.
 *
 * @param {string} rawUrl
 * @param {Object} [options={}]
 * @returns {{ isValid: boolean, error?: string, parsedUrl?: URL }}
 */
function validateSafeUrl(rawUrl, options = {}) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { isValid: false, error: 'URL must be a non-empty string' };
  }

  const allowedProtocols = options.allowedProtocols || ['https:'];
  const allowedPorts = options.allowedPorts || ['443', ''];

  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (err) {
    return { isValid: false, error: `Malformed URL format: ${err.message}` };
  }

  if (!allowedProtocols.includes(parsed.protocol)) {
    return { isValid: false, error: `Protocol "${parsed.protocol}" is not permitted. Only secure HTTPS URLs are allowed` };
  }

  if (parsed.username || parsed.password) {
    return { isValid: false, error: 'Embedding user credentials or authentication tokens in repository URLs is prohibited' };
  }

  if (parsed.port && !allowedPorts.includes(parsed.port)) {
    return { isValid: false, error: `Non-standard port "${parsed.port}" is not permitted` };
  }

  const hostname = parsed.hostname;
  if (isPrivateOrBlockedHost(hostname)) {
    return { isValid: false, error: `Host "${hostname}" resolves to a prohibited local, private, or metadata address space (SSRF protection)` };
  }

  if (options.allowedHosts && Array.isArray(options.allowedHosts)) {
    const lowerHosts = options.allowedHosts.map(h => h.toLowerCase());
    if (!lowerHosts.includes(hostname.toLowerCase())) {
      return { isValid: false, error: `Host "${hostname}" is not a supported Git host` };
    }
  }

  return { isValid: true, parsedUrl: parsed };
}

/**
 * Asynchronously validates URL and ensures resolved DNS addresses do not bypass SSRF filters.
 *
 * @param {string} rawUrl
 * @param {Object} [options={}]
 * @param {Function} [options.dnsLookup] - Optional custom dns lookup for testing
 * @returns {Promise<{ isValid: boolean, error?: string, parsedUrl?: URL, resolvedAddresses?: string[] }>}
 */
async function validateUrlAndResolveDns(rawUrl, options = {}) {
  const staticCheck = validateSafeUrl(rawUrl, options);
  if (!staticCheck.isValid) {
    return staticCheck;
  }

  const parsedUrl = staticCheck.parsedUrl;
  const hostname = parsedUrl.hostname;

  // If already an IP literal, static check already checked it
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':')) {
    return { isValid: true, parsedUrl, resolvedAddresses: [hostname] };
  }

  const lookupFn = options.dnsLookup || (async (host) => {
    return await dns.promises.lookup(host, { all: true });
  });

  let records;
  try {
    const res = await lookupFn(hostname);
    records = Array.isArray(res) ? res : [res];
  } catch (err) {
    return { isValid: false, error: `DNS resolution failed for host "${hostname}": ${err.message}` };
  }

  if (!records || records.length === 0) {
    return { isValid: false, error: `No DNS records found for host "${hostname}"` };
  }

  const resolvedAddresses = [];
  for (const record of records) {
    const address = typeof record === 'string' ? record : record.address;
    if (!address) continue;
    resolvedAddresses.push(address);

    if (isPrivateOrBlockedHost(address)) {
      return {
        isValid: false,
        error: `Host "${hostname}" resolved to prohibited private/local IP "${address}" (DNS rebinding / SSRF protection)`,
        resolvedAddresses
      };
    }
  }

  return {
    isValid: true,
    parsedUrl,
    resolvedAddresses
  };
}

/**
 * Validates an HTTP redirect target against SSRF policy.
 *
 * @param {string} originalUrl - The URL that generated the redirect
 * @param {string} redirectLocation - The Location header value
 * @param {Object} [options={}]
 * @returns {Promise<{ isValid: boolean, targetUrl?: string, error?: string }>}
 */
async function validateRedirect(originalUrl, redirectLocation, options = {}) {
  if (!redirectLocation || typeof redirectLocation !== 'string') {
    return { isValid: false, error: 'Redirect location is missing or invalid' };
  }

  let resolvedTargetUrl;
  try {
    resolvedTargetUrl = new URL(redirectLocation.trim(), originalUrl).toString();
  } catch (err) {
    return { isValid: false, error: `Failed to resolve redirect target: ${err.message}` };
  }

  const check = await validateUrlAndResolveDns(resolvedTargetUrl, options);
  if (!check.isValid) {
    return {
      isValid: false,
      targetUrl: resolvedTargetUrl,
      error: `Redirect blocked by SSRF policy: ${check.error}`
    };
  }

  return {
    isValid: true,
    targetUrl: resolvedTargetUrl,
    resolvedAddresses: check.resolvedAddresses
  };
}

module.exports = {
  isPrivateOrBlockedIPv4,
  isPrivateOrBlockedIPv6,
  parseNumericIp,
  isPrivateOrBlockedHost,
  validateSafeUrl,
  validateUrlAndResolveDns,
  validateRedirect,
  CLOUD_METADATA_HOSTS
};
