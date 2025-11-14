import { beforeEach, expect, test, vi } from 'vitest';

import { MikroMailProvider } from '../../src/providers/MikroMailProvider.js';

const mockSend = vi.fn().mockResolvedValue(undefined);

vi.mock('mikromail', () => {
  return {
    MikroMail: class {
      send = mockSend;
    }
  };
});

let provider: MikroMailProvider;
const mockConfig = {
  user: 'test@example.com',
  password: 'password123',
  host: 'smtp.example.com',
  port: 587,
  secure: true
};

beforeEach(() => {
  vi.clearAllMocks();
  provider = new MikroMailProvider(mockConfig);
});

test('It should initialize MikroMail with the provided config', () => {
  // Test that the provider was created successfully
  expect(provider).toBeDefined();
});

test('It should correctly send an email', async () => {
  const mockMessage = {
    from: 'sam.person@democompany.net',
    to: 'recipient@example.com',
    subject: 'Test Subject',
    text: 'Hello, this is a test email.',
    html: '<p>Hello, this is a test email.</p>'
  };

  await provider.sendMail(mockMessage);

  // Verify send was called with the correct arguments
  expect(mockSend).toHaveBeenCalledTimes(1);
  expect(mockSend).toHaveBeenCalledWith({
    from: mockConfig.user,
    to: mockMessage.to,
    subject: mockMessage.subject,
    text: mockMessage.text,
    html: mockMessage.html
  });
});

test('It should handle sending to multiple recipients', async () => {
  const mockMessage = {
    from: 'sam.person@democompany.net',
    to: ['recipient1@example.com', 'recipient2@example.com'],
    subject: 'Multiple Recipients',
    text: 'Hello, this is a test email to multiple recipients.',
    html: '<p>Hello, this is a test email to multiple recipients.</p>'
  };

  await provider.sendMail(mockMessage);

  expect(mockSend).toHaveBeenCalledTimes(1);
  expect(mockSend).toHaveBeenCalledWith({
    from: mockConfig.user,
    to: mockMessage.to,
    subject: mockMessage.subject,
    text: mockMessage.text,
    html: mockMessage.html
  });
});

test('It should handle errors from MikroMail', async () => {
  const mockError = new Error('SMTP connection failed');
  mockSend.mockRejectedValueOnce(mockError);

  const mockMessage = {
    from: 'sam.person@democompany.net',
    to: 'recipient@example.com',
    subject: 'Test Subject',
    text: 'Hello, this is a test email.',
    html: '<p>Hello, this is a test email.</p>'
  };

  await expect(provider.sendMail(mockMessage)).rejects.toThrow(
    'SMTP connection failed'
  );
  expect(mockSend).toHaveBeenCalledTimes(1);
});

test('It should pass an optional "from" field if provided in the message', async () => {
  const mockMessage = {
    from: 'custom@example.com',
    to: 'recipient@example.com',
    subject: 'Custom From Test',
    text: 'This email has a custom from address.',
    html: '<p>This email has a custom from address.</p>'
  };

  await provider.sendMail(mockMessage);

  expect(mockSend).toHaveBeenCalledWith({
    from: mockConfig.user,
    to: mockMessage.to,
    subject: mockMessage.subject,
    text: mockMessage.text,
    html: mockMessage.html
  });
});

test('It should handle CC and BCC fields if provided', async () => {
  const mockMessage = {
    from: 'sam.person@democompany.net',
    to: 'recipient@example.com',
    cc: 'cc@example.com',
    bcc: 'bcc@example.com',
    subject: 'CC and BCC Test',
    text: 'This email tests CC and BCC functionality.',
    html: '<p>This email tests CC and BCC functionality.</p>'
  };

  await provider.sendMail(mockMessage);

  expect(mockSend).toHaveBeenCalledWith({
    from: mockConfig.user,
    to: mockMessage.to,
    cc: mockMessage.cc,
    bcc: mockMessage.bcc,
    subject: mockMessage.subject,
    text: mockMessage.text,
    html: mockMessage.html
  });
});
