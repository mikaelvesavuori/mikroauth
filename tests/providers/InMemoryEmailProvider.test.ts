import { beforeEach, expect, test, vi } from 'vitest';

import type {
  EmailMessage,
  EmailProvider
} from '../../src/interfaces/index.js';

import { InMemoryEmailProvider } from '../../src/providers/InMemoryEmailProvider.js';

let emailService: InMemoryEmailProvider;

beforeEach(() => {
  emailService = new InMemoryEmailProvider();
});

test('It should implement EmailProvider interface', () => {
  const service: EmailProvider = emailService;
  expect(service.sendMail).toBeInstanceOf(Function);
});

test('It should store sent emails', async () => {
  const testEmail: EmailMessage = {
    from: 'test@sender.com',
    to: 'test@recipient.com',
    subject: 'Test Subject',
    text: 'Test plain text content',
    html: '<p>Test HTML content</p>'
  };

  await emailService.sendMail(testEmail);

  const sentEmails = emailService.getSentEmails();
  expect(sentEmails).toHaveLength(1);
  expect(sentEmails[0]).toEqual(testEmail);
});

test('It should store multiple emails', async () => {
  const emails = [
    {
      from: 'test1@sender.com',
      to: 'test1@recipient.com',
      subject: 'Subject 1',
      text: 'Text 1',
      html: 'HTML 1'
    },
    {
      from: 'test2@sender.com',
      to: 'test2@recipient.com',
      subject: 'Subject 2',
      text: 'Text 2',
      html: 'HTML 2'
    },
    {
      from: 'test3@sender.com',
      to: 'test3@recipient.com',
      subject: 'Subject 3',
      text: 'Text 3',
      html: 'HTML 3'
    }
  ];

  for (const email of emails) {
    await emailService.sendMail(email);
  }

  const sentEmails = emailService.getSentEmails();
  expect(sentEmails).toHaveLength(3);
  expect(sentEmails).toEqual(emails);
});

test('It should log to console when logToConsole option is true', async () => {
  emailService = new InMemoryEmailProvider({ logToConsole: true });

  const consoleSpy = vi.spyOn(console, 'log');

  const testEmail: EmailMessage = {
    from: 'test@sender.com',
    to: 'test@recipient.com',
    subject: 'Test Subject',
    text: 'Test plain text content',
    html: '<p>Test HTML content</p>'
  };

  await emailService.sendMail(testEmail);

  expect(consoleSpy).toHaveBeenCalledTimes(5); // Header + 4 email fields
  expect(consoleSpy).toHaveBeenCalledWith('Email sent:');
  expect(consoleSpy).toHaveBeenCalledWith(`From: ${testEmail.from}`);
  expect(consoleSpy).toHaveBeenCalledWith(`To: ${testEmail.to}`);
  expect(consoleSpy).toHaveBeenCalledWith(`Subject: ${testEmail.subject}`);
  expect(consoleSpy).toHaveBeenCalledWith(`Text: ${testEmail.text}`);

  consoleSpy.mockRestore();
});

test('It should not log to console when logToConsole option is false', async () => {
  emailService = new InMemoryEmailProvider({ logToConsole: false });

  const consoleSpy = vi.spyOn(console, 'log');

  const testEmail: EmailMessage = {
    from: 'test@sender.com',
    to: 'test@recipient.com',
    subject: 'Test Subject',
    text: 'Test content',
    html: '<p>Test content</p>'
  };

  await emailService.sendMail(testEmail);

  expect(consoleSpy).not.toHaveBeenCalled();

  consoleSpy.mockRestore();
});

test('It should call onSend callback if provided', async () => {
  const onSendMock = vi.fn();

  emailService = new InMemoryEmailProvider({ onSend: onSendMock });

  const testEmail: EmailMessage = {
    from: 'test@sender.com',
    to: 'test@recipient.com',
    subject: 'Test Subject',
    text: 'Test content',
    html: '<p>Test content</p>'
  };

  await emailService.sendMail(testEmail);

  expect(onSendMock).toHaveBeenCalledTimes(1);
  expect(onSendMock).toHaveBeenCalledWith(testEmail);
});

test('It should return a copy of emails, not the original array', async () => {
  const testEmail: EmailMessage = {
    from: 'test@sender.com',
    to: 'test@recipient.com',
    subject: 'Test Subject',
    text: 'Test content',
    html: '<p>Test content</p>'
  };

  await emailService.sendMail(testEmail);

  const sentEmails = emailService.getSentEmails();

  sentEmails.push({
    from: 'another@sender.com',
    to: 'another@recipient.com',
    subject: 'Another Subject',
    text: 'Another content',
    html: '<p>Another content</p>'
  });

  const sentEmailsAfter = emailService.getSentEmails();
  expect(sentEmailsAfter).toHaveLength(1);
});

test('It should remove all stored emails', async () => {
  for (let i = 0; i < 3; i++) {
    await emailService.sendMail({
      from: `test${i}@sender.com`,
      to: `test${i}@recipient.com`,
      subject: `Subject ${i}`,
      text: `Text ${i}`,
      html: `HTML ${i}`
    });
  }

  expect(emailService.getSentEmails()).toHaveLength(3);

  emailService.clearSentEmails();

  expect(emailService.getSentEmails()).toHaveLength(0);
});
