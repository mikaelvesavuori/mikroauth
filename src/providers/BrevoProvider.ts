import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description Brevo (formerly Sendinblue) email provider using their HTTP API.
 * @see https://developers.brevo.com/docs/send-a-transactional-email
 */
export class BrevoProvider implements EmailProvider {
  private readonly apiKey: string;
  private readonly debug: boolean;

  constructor(config: { apiKey: string; debug?: boolean }) {
    if (!config.apiKey) {
      throw new Error('BrevoProvider requires an apiKey');
    }
    this.apiKey = config.apiKey;
    this.debug = config.debug ?? false;
  }

  /**
   * @description Send an email using the Brevo API.
   */
  public async sendMail(message: EmailMessage): Promise<void> {
    const endpoint = 'https://api.brevo.com/v3/smtp/email';

    // Parse sender email and name
    const senderMatch = message.from.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
    const senderName = senderMatch?.[1]?.trim() || '';
    const senderEmail = senderMatch?.[2]?.trim() || message.from;

    // Convert recipients to Brevo format
    const toArray = Array.isArray(message.to) ? message.to : [message.to];
    const to = toArray.map((recipient) => {
      const match = recipient.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
      return {
        email: match?.[2]?.trim() || recipient,
        ...(match?.[1] && { name: match[1].trim() })
      };
    });

    const body: Record<string, any> = {
      sender: {
        email: senderEmail,
        ...(senderName && { name: senderName })
      },
      to,
      subject: message.subject,
      htmlContent: message.html,
      textContent: message.text
    };

    // Add cc if present
    if (message.cc) {
      const ccArray = Array.isArray(message.cc) ? message.cc : [message.cc];
      body.cc = ccArray.map((recipient) => {
        const match = recipient.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
        return {
          email: match?.[2]?.trim() || recipient,
          ...(match?.[1] && { name: match[1].trim() })
        };
      });
    }

    // Add bcc if present
    if (message.bcc) {
      const bccArray = Array.isArray(message.bcc) ? message.bcc : [message.bcc];
      body.bcc = bccArray.map((recipient) => {
        const match = recipient.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
        return {
          email: match?.[2]?.trim() || recipient,
          ...(match?.[1] && { name: match[1].trim() })
        };
      });
    }

    if (this.debug) {
      console.log('[BrevoProvider] Sending email:', {
        endpoint,
        to: body.to,
        subject: body.subject
      });
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'api-key': this.apiKey,
        'content-type': 'application/json',
        accept: 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const error = new Error(
        `Brevo API error: ${response.status} ${response.statusText}`
      );
      (error as any).status = response.status;
      (error as any).response = errorData;

      if (this.debug) {
        console.error('[BrevoProvider] Error:', error);
      }

      throw error;
    }

    const result = await response.json();

    if (this.debug) {
      console.log('[BrevoProvider] Email sent successfully:', result);
    }
  }
}
