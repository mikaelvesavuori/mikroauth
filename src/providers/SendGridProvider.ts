import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description SendGrid email provider using their v3 HTTP API.
 * @see https://www.twilio.com/docs/sendgrid/api-reference/mail-send/mail-send
 */
export class SendGridProvider implements EmailProvider {
  private readonly apiKey: string;
  private readonly debug: boolean;

  constructor(config: { apiKey: string; debug?: boolean }) {
    if (!config.apiKey) {
      throw new Error('SendGridProvider requires an apiKey');
    }
    this.apiKey = config.apiKey;
    this.debug = config.debug ?? false;
  }

  /**
   * @description Send an email using the SendGrid v3 API.
   */
  public async sendMail(message: EmailMessage): Promise<void> {
    const endpoint = 'https://api.sendgrid.com/v3/mail/send';

    // Parse sender email and name
    const fromMatch = message.from.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
    const fromName = fromMatch?.[1]?.trim();
    const fromEmail = fromMatch?.[2]?.trim() || message.from;

    // Convert recipients to SendGrid format
    const toArray = Array.isArray(message.to) ? message.to : [message.to];
    const to = toArray.map((recipient) => {
      const match = recipient.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
      return {
        email: match?.[2]?.trim() || recipient,
        ...(match?.[1] && { name: match[1].trim() })
      };
    });

    const body: Record<string, any> = {
      personalizations: [
        {
          to
        }
      ],
      from: {
        email: fromEmail,
        ...(fromName && { name: fromName })
      },
      subject: message.subject,
      content: []
    };

    // Add content (text and/or html)
    if (message.text) {
      body.content.push({
        type: 'text/plain',
        value: message.text
      });
    }

    if (message.html) {
      body.content.push({
        type: 'text/html',
        value: message.html
      });
    }

    // Add cc if present
    if (message.cc) {
      const ccArray = Array.isArray(message.cc) ? message.cc : [message.cc];
      const cc = ccArray.map((recipient) => {
        const match = recipient.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
        return {
          email: match?.[2]?.trim() || recipient,
          ...(match?.[1] && { name: match[1].trim() })
        };
      });
      body.personalizations[0].cc = cc;
    }

    // Add bcc if present
    if (message.bcc) {
      const bccArray = Array.isArray(message.bcc) ? message.bcc : [message.bcc];
      const bcc = bccArray.map((recipient) => {
        const match = recipient.match(/^(?:"?([^"]*)"?\s)?<?([^>]+)>?$/);
        return {
          email: match?.[2]?.trim() || recipient,
          ...(match?.[1] && { name: match[1].trim() })
        };
      });
      body.personalizations[0].bcc = bcc;
    }

    if (this.debug) {
      console.log('[SendGridProvider] Sending email:', {
        endpoint,
        to: body.personalizations[0].to,
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
        `SendGrid API error: ${response.status} ${response.statusText}`
      );
      (error as any).status = response.status;
      (error as any).response = errorData;

      if (this.debug) {
        console.error('[SendGridProvider] Error:', error);
      }

      throw error;
    }

    if (this.debug) {
      console.log('[SendGridProvider] Email sent successfully');
    }
  }
}
