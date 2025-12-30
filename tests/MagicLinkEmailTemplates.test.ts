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

test('It should accept and pass metadata to custom templates', () => {
  const link = 'https://example.com/auth?token=abc123';
  const minutes = 15;
  const metadata = {
    userName: 'John Doe',
    companyName: 'ACME Corp',
    loginAttempts: 1
  };

  const magicLinkTemplates = new MagicLinkEmailTemplates({
    textVersion: (
      magicLink: string,
      expiryMinutes: number,
      meta?: Record<string, any>
    ) =>
      `Hello ${meta?.userName || 'User'}! Welcome to ${meta?.companyName || 'our service'}. Click here to login: ${magicLink}. Link expires in ${expiryMinutes} minutes. Login attempt: ${meta?.loginAttempts || 0}.`,
    htmlVersion: (
      magicLink: string,
      expiryMinutes: number,
      meta?: Record<string, any>
    ) =>
      `<h1>Hello ${meta?.userName || 'User'}!</h1><p>Welcome to ${meta?.companyName || 'our service'}.</p><a href="${magicLink}">Login</a><p>Expires in ${expiryMinutes} minutes.</p>`
  });

  const text = magicLinkTemplates.getText(link, minutes, metadata);
  const html = magicLinkTemplates.getHtml(link, minutes, metadata);

  expect(text).toContain('Hello John Doe!');
  expect(text).toContain('Welcome to ACME Corp');
  expect(text).toContain('Login attempt: 1');
  expect(html).toContain('Hello John Doe!');
  expect(html).toContain('Welcome to ACME Corp');
});

test('It should handle metadata with conditional rendering', () => {
  const link = 'https://example.com/auth?token=abc123';
  const minutes = 15;

  const magicLinkTemplates = new MagicLinkEmailTemplates({
    textVersion: (
      magicLink: string,
      expiryMinutes: number,
      meta?: Record<string, any>
    ) => {
      let text = `Login link: ${magicLink}\nExpires in ${expiryMinutes} minutes.`;
      if (meta?.isNewUser) {
        text += '\nWelcome to our platform! This is your first login.';
      }
      if (meta?.specialOffer) {
        text += `\n${meta.specialOffer}`;
      }
      return text;
    },
    htmlVersion: (
      magicLink: string,
      expiryMinutes: number,
      meta?: Record<string, any>
    ) => {
      let html = `<a href="${magicLink}">Login</a><p>Expires in ${expiryMinutes} minutes.</p>`;
      if (meta?.isNewUser) {
        html += '<p>Welcome! This is your first login.</p>';
      }
      if (meta?.specialOffer) {
        html += `<p>${meta.specialOffer}</p>`;
      }
      return html;
    }
  });

  const textWithOffer = magicLinkTemplates.getText(link, minutes, {
    isNewUser: true,
    specialOffer: 'Get 20% off your first order!'
  });
  const htmlWithOffer = magicLinkTemplates.getHtml(link, minutes, {
    isNewUser: true,
    specialOffer: 'Get 20% off your first order!'
  });

  expect(textWithOffer).toContain(
    'Welcome to our platform! This is your first login.'
  );
  expect(textWithOffer).toContain('Get 20% off your first order!');
  expect(htmlWithOffer).toContain('Welcome! This is your first login.');
  expect(htmlWithOffer).toContain('Get 20% off your first order!');

  const textWithoutMeta = magicLinkTemplates.getText(link, minutes);
  expect(textWithoutMeta).not.toContain('Welcome to our platform');
  expect(textWithoutMeta).not.toContain('Get 20% off');
});

test('It should handle metadata with arrays and complex objects', () => {
  const link = 'https://example.com/auth?token=abc123';
  const minutes = 15;
  const metadata = {
    recentActivity: [
      'Viewed product A',
      'Added item to cart',
      'Started checkout'
    ],
    userPreferences: {
      language: 'en',
      theme: 'dark'
    },
    accountAge: 365
  };

  const magicLinkTemplates = new MagicLinkEmailTemplates({
    textVersion: (
      magicLink: string,
      _expiryMinutes: number,
      meta?: Record<string, any>
    ) => {
      let text = `Login: ${magicLink}\n`;
      if (meta?.recentActivity && Array.isArray(meta.recentActivity)) {
        text += `Recent activity:\n${meta.recentActivity.map((item: string) => `- ${item}`).join('\n')}\n`;
      }
      if (meta?.userPreferences?.language) {
        text += `Preferred language: ${meta.userPreferences.language}\n`;
      }
      return text;
    },
    htmlVersion: (
      magicLink: string,
      _expiryMinutes: number,
      meta?: Record<string, any>
    ) => {
      let html = `<a href="${magicLink}">Login</a>`;
      if (meta?.recentActivity && Array.isArray(meta.recentActivity)) {
        html += `<ul>${meta.recentActivity.map((item: string) => `<li>${item}</li>`).join('')}</ul>`;
      }
      return html;
    }
  });

  const text = magicLinkTemplates.getText(link, minutes, metadata);
  const html = magicLinkTemplates.getHtml(link, minutes, metadata);

  expect(text).toContain('Viewed product A');
  expect(text).toContain('Added item to cart');
  expect(text).toContain('Preferred language: en');
  expect(html).toContain('<li>Viewed product A</li>');
  expect(html).toContain('<li>Added item to cart</li>');
});

test('It should work with default templates when metadata is passed but not used', () => {
  const link = 'https://example.com/auth?token=abc123';
  const minutes = 15;
  const metadata = { someKey: 'someValue' };

  const magicLinkTemplates = new MagicLinkEmailTemplates();

  const text = magicLinkTemplates.getText(link, minutes, metadata);
  const html = magicLinkTemplates.getHtml(link, minutes, metadata);

  expect(text).toContain(link);
  expect(text).toContain(`Expires in ${minutes} minutes`);
  expect(html).toContain(`href="${link}"`);
  expect(html).toContain(`This link expires in ${minutes} minutes`);
});
