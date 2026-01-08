import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { ResendProvider } from '../../src/providers/ResendProvider.js';

describe('ResendProvider', () => {
  let provider: ResendProvider;
  let fetchSpy: any;

  beforeEach(() => {
    provider = new ResendProvider({ apiKey: 'test-api-key' });
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw error if apiKey is not provided', () => {
    expect(() => new ResendProvider({} as any)).toThrow(
      'ResendProvider requires an apiKey'
    );
  });

  it('should send email successfully', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer test-api-key',
          'Content-Type': 'application/json'
        })
      })
    );

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.from).toBe('sender@example.com');
    expect(requestBody.to).toEqual(['recipient@example.com']);
    expect(requestBody.subject).toBe('Test Subject');
    expect(requestBody.text).toBe('Test text');
    expect(requestBody.html).toBe('<p>Test html</p>');
  });

  it('should handle multiple recipients', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: ['recipient1@example.com', 'recipient2@example.com'],
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.to).toEqual([
      'recipient1@example.com',
      'recipient2@example.com'
    ]);
  });

  it('should handle cc and bcc', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'test-message-id' })
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
    expect(requestBody.cc).toEqual(['cc@example.com']);
    expect(requestBody.bcc).toEqual(['bcc1@example.com', 'bcc2@example.com']);
  });

  it('should throw error on API failure', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      json: async () => ({ error: 'Invalid email' })
    });

    await expect(
      provider.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        text: 'Test text',
        html: '<p>Test html</p>'
      })
    ).rejects.toThrow('Resend API error: 400 Bad Request');
  });
});
