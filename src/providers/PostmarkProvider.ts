import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description Postmark email provider using their HTTP API.
 * @see https://postmarkapp.com/developer/api/email-api
 */
export class PostmarkProvider implements EmailProvider {
  private readonly serverToken: string;
  private readonly messageStream: string;
  private readonly debug: boolean;

  constructor(config: {
    serverToken: string;
    messageStream?: string;
    debug?: boolean;
  }) {
    if (!config.serverToken) {
      throw new Error('PostmarkProvider requires a serverToken');
    }
    this.serverToken = config.serverToken;
    this.messageStream = config.messageStream ?? 'outbound';
    this.debug = config.debug ?? false;
  }

  /**
   * @description Send an email using the Postmark API.
   */
  public async sendMail(message: EmailMessage): Promise<void> {
    const endpoint = 'https://api.postmarkapp.com/email';

    const body: Record<string, any> = {
      From: message.from,
      To: Array.isArray(message.to) ? message.to.join(',') : message.to,
      Subject: message.subject,
      HtmlBody: message.html,
      TextBody: message.text,
      MessageStream: this.messageStream
    };

    // Add Cc if present
    if (message.cc) {
      body.Cc = Array.isArray(message.cc) ? message.cc.join(',') : message.cc;
    }

    // Add Bcc if present
    if (message.bcc) {
      body.Bcc = Array.isArray(message.bcc)
        ? message.bcc.join(',')
        : message.bcc;
    }

    if (this.debug) {
      console.log('[PostmarkProvider] Sending email:', {
        endpoint,
        To: body.To,
        Subject: body.Subject
      });
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'X-Postmark-Server-Token': this.serverToken,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const error = new Error(
        `Postmark API error: ${response.status} ${response.statusText}`
      );
      (error as any).status = response.status;
      (error as any).response = errorData;

      if (this.debug) {
        console.error('[PostmarkProvider] Error:', error);
      }

      throw error;
    }

    const result = await response.json();

    if (this.debug) {
      console.log('[PostmarkProvider] Email sent successfully:', result);
    }
  }
}
