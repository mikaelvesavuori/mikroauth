import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { SendGridProvider } from '../../src/providers/SendGridProvider.js';

describe('SendGridProvider', () => {
  let provider: SendGridProvider;
  let fetchSpy: any;

  beforeEach(() => {
    provider = new SendGridProvider({ apiKey: 'test-api-key' });
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw error if apiKey is not provided', () => {
    expect(() => new SendGridProvider({} as any)).toThrow(
      'SendGridProvider requires an apiKey'
    );
  });

  it('should send email successfully', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({})
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.sendgrid.com/v3/mail/send',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer test-api-key',
          'Content-Type': 'application/json'
        })
      })
    );

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.from.email).toBe('sender@example.com');
    expect(requestBody.personalizations[0].to).toEqual([
      { email: 'recipient@example.com' }
    ]);
    expect(requestBody.subject).toBe('Test Subject');
    expect(requestBody.content).toContainEqual({
      type: 'text/plain',
      value: 'Test text'
    });
    expect(requestBody.content).toContainEqual({
      type: 'text/html',
      value: '<p>Test html</p>'
    });
  });

  it('should parse sender name from email', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({})
    });

    await provider.sendMail({
      from: '"John Doe" <sender@example.com>',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.from.email).toBe('sender@example.com');
    expect(requestBody.from.name).toBe('John Doe');
  });

  it('should handle multiple recipients', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({})
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: ['"Jane Doe" <jane@example.com>', 'bob@example.com'],
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.personalizations[0].to).toEqual([
      { email: 'jane@example.com', name: 'Jane Doe' },
      { email: 'bob@example.com' }
    ]);
  });

  it('should handle cc and bcc', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({})
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      cc: 'cc@example.com',
      bcc: ['bcc1@example.com', 'bcc2@example.com'],
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.personalizations[0].cc).toEqual([
      { email: 'cc@example.com' }
    ]);
    expect(requestBody.personalizations[0].bcc).toEqual([
      { email: 'bcc1@example.com' },
      { email: 'bcc2@example.com' }
    ]);
  });

  it('should throw error on API failure', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      json: async () => ({ errors: [{ message: 'Invalid email format' }] })
    });

    await expect(
      provider.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        text: 'Test text',
        html: '<p>Test html</p>'
      })
    ).rejects.toThrow('SendGrid API error: 400 Bad Request');
  });
});
