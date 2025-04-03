import { MikroMail } from 'mikromail';

import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description Use MikroMail as the email provider.
 * @see https://github.com/mikaelvesavuori/mikromail
 */
export class MikroMailProvider implements EmailProvider {
  private readonly email: MikroMail;
  private readonly sender: string;

  constructor(config: Record<string, any>) {
    this.sender = config.user;
    this.email = new MikroMail({ config: config as any });
  }

  /**
   * @description Send an email using the MikroMail provider.
   */
  public async sendMail(message: EmailMessage): Promise<void> {
    await this.email.send({
      from: this.sender,
      to: message.to,
      cc: message.cc,
      bcc: message.bcc,
      subject: message.subject,
      text: message.text,
      html: message.html
    });
  }
}
