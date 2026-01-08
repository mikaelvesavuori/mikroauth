import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { BrevoProvider } from '../../src/providers/BrevoProvider.js';

describe('BrevoProvider', () => {
  let provider: BrevoProvider;
  let fetchSpy: any;

  beforeEach(() => {
    provider = new BrevoProvider({ apiKey: 'test-api-key' });
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw error if apiKey is not provided', () => {
    expect(() => new BrevoProvider({} as any)).toThrow(
      'BrevoProvider requires an apiKey'
    );
  });

  it('should send email successfully', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ messageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.brevo.com/v3/smtp/email',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'api-key': 'test-api-key',
          'content-type': 'application/json'
        })
      })
    );

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.sender.email).toBe('sender@example.com');
    expect(requestBody.to).toEqual([{ email: 'recipient@example.com' }]);
    expect(requestBody.subject).toBe('Test Subject');
  });

  it('should parse sender name from email', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ messageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: '"John Doe" <sender@example.com>',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.sender.email).toBe('sender@example.com');
    expect(requestBody.sender.name).toBe('John Doe');
  });

  it('should handle multiple recipients with names', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ messageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: ['"Jane Doe" <jane@example.com>', 'bob@example.com'],
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.to).toEqual([
      { email: 'jane@example.com', name: 'Jane Doe' },
      { email: 'bob@example.com' }
    ]);
  });

  it('should throw error on API failure', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ message: 'Invalid API key' })
    });

    await expect(
      provider.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        text: 'Test text',
        html: '<p>Test html</p>'
      })
    ).rejects.toThrow('Brevo API error: 401 Unauthorized');
  });
});
