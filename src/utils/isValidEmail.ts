/**
 * @description Validates if an email address is in a correct format.
 *
 * Checks for:
 * - Standard email format (username@domain.tld)
 * - Local part with dots, plus signs, and other valid special characters
 * - Quoted local parts (with special characters)
 * - Multiple subdomains (user@sub.example.com)
 * - Single-level domains (admin@mailserver1)
 * - IP addresses in brackets ([192.168.1.1] and [IPv6:2001:db8::1])
 * - No consecutive dots anywhere in the email
 * - No invalid characters in the username or domain
 * - No multiple @ symbols
 */
export function isValidEmail(email: string): boolean {
  if (!email || email.trim() === '') return false;

  const atSymbolCount = (email.match(/@/g) || []).length;
  if (atSymbolCount !== 1) return false;

  const [localPart, domain] = email.split('@');
  if (!localPart || !domain) return false;

  if (email.includes('..')) return false;

  if (!isValidLocalPart(localPart)) return false;

  if (!isValidDomain(domain)) return false;

  return true;
}

/**
 * @description Validates the local part (before @) of an email address.
 */
function isValidLocalPart(localPart: string): boolean {
  if (localPart.startsWith('"') && localPart.endsWith('"')) {
    const quotedContent = localPart.slice(1, -1);
    return !quotedContent.includes('"');
  }

  if (localPart.length > 64) return false;

  if (localPart.startsWith('.') || localPart.endsWith('.')) return false;

  const validLocalPartRegex = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$/;
  return validLocalPartRegex.test(localPart);
}

/**
 * @description Validates the domain part (after @) of an email address.
 */
function isValidDomain(domain: string): boolean {
  if (domain.startsWith('[') && domain.endsWith(']')) {
    const ipContent = domain.slice(1, -1);

    if (ipContent.startsWith('IPv6:')) return isValidIPv6(ipContent.slice(5));

    return isValidIPv4(ipContent);
  }

  const domainParts = domain.split('.');

  if (domainParts.length === 0) return false;

  for (const part of domainParts) {
    if (!part || part.length > 63) return false;

    const validDomainPartRegex =
      /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    if (!validDomainPartRegex.test(part)) return false;
  }

  if (domainParts.length > 1) {
    const tld = domainParts[domainParts.length - 1];
    const validTldRegex = /^[a-zA-Z]{2,}$/;
    if (!validTldRegex.test(tld)) return false;
  }

  return true;
}

/**
 * @description Validates an IPv4 address.
 */
function isValidIPv4(ip: string): boolean {
  const ipv4Regex =
    /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/;
  return ipv4Regex.test(ip);
}

/**
 * @description Validates an IPv6 address (simplified).
 */
function isValidIPv6(ip: string): boolean {
  const ipv6Regex = /^[a-fA-F0-9:]+$/;
  if (!ipv6Regex.test(ip)) return false;

  const parts = ip.split(':');
  if (parts.length < 2 || parts.length > 8) return false;

  return true;
}
