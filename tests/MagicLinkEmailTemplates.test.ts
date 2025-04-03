import { expect, test } from 'vitest';

import { MagicLinkEmailTemplates } from '../src/MagicLinkEmailTemplates.js';

const magicLinkTemplates = new MagicLinkEmailTemplates();

test('It should return properly formatted text with link and expiry', () => {
  const magicLink = 'https://example.com/auth?token=abc123';
  const expiryMinutes = 15;

  const text = magicLinkTemplates.getText(magicLink, expiryMinutes);

  expect(text).toContain(magicLink);
  expect(text).toContain(`Expires in ${expiryMinutes} minutes`);
  expect(text).toContain('Can only be used once');
  expect(text).toContain('Should only be used by you');
  expect(text).toContain("If you didn't request this link");
});

test('It should return properly formatted HTML with link and expiry', () => {
  const magicLink = 'https://example.com/auth?token=abc123';
  const expiryMinutes = 15;

  const html = magicLinkTemplates.getHtml(magicLink, expiryMinutes);

  expect(html).toContain('<!DOCTYPE html>');
  expect(html).toContain('<html>');
  expect(html).toContain('<head>');
  expect(html).toContain('<body>');
  expect(html).toContain('<style>');
  expect(html).toContain(`href="${magicLink}"`);
  expect(html).toContain(`This link expires in ${expiryMinutes} minutes`);
  expect(html).toContain('Login to Your Account');
  expect(html).toContain('Security Information');
});

test('It should handle different expiry times', () => {
  const magicLink = 'https://example.com/auth?token=abc123';
  const expiryTimes = [1, 5, 10, 15, 30, 60, 120];

  for (const minutes of expiryTimes) {
    const text = magicLinkTemplates.getText(magicLink, minutes);
    const html = magicLinkTemplates.getHtml(magicLink, minutes);

    expect(text).toContain(`Expires in ${minutes} minutes`);
    expect(html).toContain(`This link expires in ${minutes} minutes`);
  }
});

test('It should handle special characters in magic links', () => {
  const specialCharsLink =
    'https://example.com/auth?token=abc123&special=!@#$%^&*()_+';
  const expiryMinutes = 15;

  const text = magicLinkTemplates.getText(specialCharsLink, expiryMinutes);
  const html = magicLinkTemplates.getHtml(specialCharsLink, expiryMinutes);

  expect(text).toContain(specialCharsLink);
  expect(html).toContain(`href="${specialCharsLink}"`);
});

test('It should handle very long magic links', () => {
  const longToken = 'a'.repeat(100) + 'b'.repeat(100) + 'c'.repeat(100);
  const longLink = `https://example.com/auth?token=${longToken}&email=test@example.com`;
  const expiryMinutes = 15;

  const text = magicLinkTemplates.getText(longLink, expiryMinutes);
  const html = magicLinkTemplates.getHtml(longLink, expiryMinutes);

  expect(text).toContain(longLink);
  expect(html).toContain(`href="${longLink}"`);

  expect(html.startsWith('<!DOCTYPE html')).toBeTruthy();
  expect(html.includes('</html>')).toBeTruthy();
});

test('It should properly encode HTML entities in magic links', () => {
  const linksToTest = [
    'https://example.com/auth?token=abc<123>&email=test@example.com',
    'https://example.com/auth?token="quoted"&email=test@example.com',
    'https://example.com/auth?token=abc&email=test@example.com&param=value with spaces'
  ];

  for (const link of linksToTest) {
    const html = magicLinkTemplates.getHtml(link, 15);

    expect(html).toContain(`href="${link}"`);

    expect(html.includes('<!DOCTYPE html')).toBeTruthy();
    expect(html.includes('</html>')).toBeTruthy();
  }
});

test('Text and HTML templates should be consistent with each other', () => {
  const link = 'https://example.com/auth?token=abc123';
  const minutes = 15;

  const text = magicLinkTemplates.getText(link, minutes);
  const html = magicLinkTemplates.getHtml(link, minutes);

  const keyPhrases = [
    link,
    `${minutes} minutes`,
    'Can only be used once',
    'Should only be used by you',
    "If you didn't request this link"
  ];

  for (const phrase of keyPhrases) {
    expect(text).toContain(phrase);
    expect(html).toContain(phrase);
  }
});

test('It should handle custom templates', () => {
  const link = 'https://example.com/auth?token=abc123';
  const minutes = 15;

  const magicLinkTemplates = new MagicLinkEmailTemplates({
    textVersion: (magicLink: string, expiryMinutes: number) =>
      `My custom text template going to "${magicLink}" with an expiry time of ${expiryMinutes} minutes.`,
    htmlVersion: (magicLink: string, expiryMinutes: number) =>
      `<h1>Custom template</h1><p>My custom HTML template going to <a href="${magicLink}">${magicLink}</a> with an expiry time of <strong>${expiryMinutes}</strong> minutes.</p>`
  });

  const text = magicLinkTemplates.getText(link, minutes);
  const html = magicLinkTemplates.getHtml(link, minutes);

  expect(text).toBe(
    'My custom text template going to "https://example.com/auth?token=abc123" with an expiry time of 15 minutes.'
  );
  expect(html).toBe(
    '<h1>Custom template</h1><p>My custom HTML template going to <a href="https://example.com/auth?token=abc123">https://example.com/auth?token=abc123</a> with an expiry time of <strong>15</strong> minutes.</p>'
  );
});
