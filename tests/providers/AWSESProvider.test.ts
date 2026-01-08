import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import { AWSESProvider } from '../../src/providers/AWSESProvider.js';

describe('AWSESProvider', () => {
  let provider: AWSESProvider;
  let fetchSpy: any;

  beforeEach(() => {
    provider = new AWSESProvider({
      accessKeyId: 'test-access-key',
      secretAccessKey: 'test-secret-key',
      region: 'us-east-1'
    });
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw error if required config is not provided', () => {
    expect(() => new AWSESProvider({} as any)).toThrow(
      'AWSESProvider requires accessKeyId, secretAccessKey, and region'
    );
  });

  it('should send email successfully', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ MessageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://email.us-east-1.amazonaws.com/v2/email/outbound-emails',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'content-type': 'application/json',
          host: 'email.us-east-1.amazonaws.com',
          'x-amz-date': expect.any(String),
          Authorization: expect.stringContaining('AWS4-HMAC-SHA256')
        })
      })
    );

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.FromEmailAddress).toBe('sender@example.com');
    expect(requestBody.Destination.ToAddresses).toEqual([
      'recipient@example.com'
    ]);
    expect(requestBody.Content.Simple.Subject.Data).toBe('Test Subject');
  });

  it('should handle multiple recipients', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ MessageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: ['recipient1@example.com', 'recipient2@example.com'],
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.Destination.ToAddresses).toEqual([
      'recipient1@example.com',
      'recipient2@example.com'
    ]);
  });

  it('should handle cc and bcc', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ MessageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      cc: ['cc1@example.com', 'cc2@example.com'],
      bcc: 'bcc@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const requestBody = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(requestBody.Destination.CcAddresses).toEqual([
      'cc1@example.com',
      'cc2@example.com'
    ]);
    expect(requestBody.Destination.BccAddresses).toEqual(['bcc@example.com']);
  });

  it('should generate proper AWS Signature V4', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ MessageId: 'test-message-id' })
    });

    await provider.sendMail({
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Test Subject',
      text: 'Test text',
      html: '<p>Test html</p>'
    });

    const headers = fetchSpy.mock.calls[0][1].headers;
    expect(headers.Authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=test-access-key\/\d{8}\/us-east-1\/ses\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[a-f0-9]{64}$/
    );
  });

  it('should throw error on API failure', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      text: async () => '<Error><Message>Invalid address</Message></Error>'
    });

    await expect(
      provider.sendMail({
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        text: 'Test text',
        html: '<p>Test html</p>'
      })
    ).rejects.toThrow('AWS SES API error: 400 Bad Request');
  });
});
