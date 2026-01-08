import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { PostmarkProvider } from '../../src/providers/PostmarkProvider.js';

describe('PostmarkProvider', () => {
  let provider: PostmarkProvider;
  let fetchSpy: any;

  beforeEach(() => {
    provider = new PostmarkProvider({ serverToken: 'test-server-token' });
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw error if serverToken is not provided', () => {
    expect(() => new PostmarkProvider({} as any)).toThrow(
      'PostmarkProvider requires a serverToken'
    );
  });

  it('should send email successfully', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        To: 'recipient@example.com',
        MessageID: 'test-message-id',
        ErrorCode: 0,
        Message: 'OK'
      })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://api.postmarkapp.com/email',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'X-Postmark-Server-Token': 'test-server-token',
          'Content-Type': 'application/json'
        })
      })
    );

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.From).toBe('sender@example.com');
    expect(requestBody.To).toBe('recipient@example.com');
    expect(requestBody.Subject).toBe('Test Subject');
    expect(requestBody.MessageStream).toBe('outbound');
  });

  it('should use custom message stream', async () => {
    const customProvider = new PostmarkProvider({
      serverToken: 'test-server-token',
      messageStream: 'custom-stream'
    });

    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ MessageID: 'test-message-id' })
    });

    await customProvider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.MessageStream).toBe('custom-stream');
  });

  it('should handle multiple recipients as comma-separated string', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ MessageID: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: ['recipient1@example.com', 'recipient2@example.com'],
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.To).toBe(
      'recipient1@example.com,recipient2@example.com'
    );
  });

  it('should throw error on API failure', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Entity',
      json: async () => ({ ErrorCode: 300, Message: 'Invalid email address' })
    });

    await expect(
      provider.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        text: 'Test text',
        html: '<p>Test html</p>'
      })
    ).rejects.toThrow('Postmark API error: 422 Unprocessable Entity');
  });
});
