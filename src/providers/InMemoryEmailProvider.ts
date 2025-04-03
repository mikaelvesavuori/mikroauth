import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description Mock implementation of EmailProvider
 * for development and testing purposes.
 */
export class InMemoryEmailProvider implements EmailProvider {
  private sentEmails: EmailMessage[] = [];

  constructor(
    private options?: {
      logToConsole?: boolean;
      onSend?: (message: EmailMessage) => void;
    }
  ) {}

  /**
   * @description Send an email with the in-memory provider.
   */
  async sendMail(message: EmailMessage): Promise<void> {
    this.sentEmails.push(message);

    if (this.options?.logToConsole) {
      console.log('Email sent:');
      console.log(`From: ${message.from}`);
      console.log(`To: ${message.to}`);
      console.log(`Subject: ${message.subject}`);
      console.log(`Text: ${message.text}`);
    }

    if (this.options?.onSend) this.options.onSend(message);
  }

  /**
   * @description Get all sent emails (for testing purposes).
   */
  getSentEmails(): EmailMessage[] {
    return [...this.sentEmails];
  }

  /**
   * @description Clear sent emails history (for testing purposes).
   */
  clearSentEmails(): void {
    this.sentEmails = [];
  }
}
