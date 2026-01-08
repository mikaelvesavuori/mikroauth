import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description Resend email provider using their HTTP API.
 * @see https://resend.com/docs/api-reference/emails/send-email
 */
export class ResendProvider implements EmailProvider {
  private readonly apiKey: string;
  private readonly debug: boolean;

  constructor(config: { apiKey: string; debug?: boolean }) {
    if (!config.apiKey) {
      throw new Error('ResendProvider requires an apiKey');
    }
    this.apiKey = config.apiKey;
    this.debug = config.debug ?? false;
  }

  /**
   * @description Send an email using the Resend API.
   */
  public async sendMail(message: EmailMessage): Promise<void> {
    const endpoint = 'https://api.resend.com/emails';

    const body = {
      from: message.from,
      to: Array.isArray(message.to) ? message.to : [message.to],
      subject: message.subject,
      html: message.html,
      text: message.text,
      ...(message.cc && {
        cc: Array.isArray(message.cc) ? message.cc : [message.cc]
      }),
      ...(message.bcc && {
        bcc: Array.isArray(message.bcc) ? message.bcc : [message.bcc]
      })
    };

    if (this.debug) {
      console.log('[ResendProvider] Sending email:', {
        endpoint,
        to: body.to,
        subject: body.subject
      });
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const error = new Error(
        `Resend API error: ${response.status} ${response.statusText}`
      );
      (error as any).status = response.status;
      (error as any).response = errorData;

      if (this.debug) {
        console.error('[ResendProvider] Error:', error);
      }

      throw error;
    }

    const result = await response.json();

    if (this.debug) {
      console.log('[ResendProvider] Email sent successfully:', result);
    }
  }
}
