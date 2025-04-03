import type { EmailTemplateConfiguration } from './interfaces';

/**
 * @description Email templates with text and HTML versions.
 */
export class MagicLinkEmailTemplates {
  private readonly templates: EmailTemplateConfiguration;

  constructor(templateConfig?: EmailTemplateConfiguration | null | undefined) {
    if (templateConfig) {
      this.templates = templateConfig;
    } else this.templates = templateDefaults;
  }

  /**
   * @description Create the text content for a magic link email.
   */
  getText(magicLink: string, expiryMinutes: number): string {
    return this.templates.textVersion(magicLink, expiryMinutes).trim();
  }

  /**
   * @description Create the HTML content for a magic link email.
   */
  getHtml(magicLink: string, expiryMinutes: number): string {
    return this.templates.htmlVersion(magicLink, expiryMinutes).trim();
  }
}

const templateDefaults = {
  textVersion: (magicLink: string, expiryMinutes: number) => `
Click this link to login: ${magicLink}

Security Information:
- Expires in ${expiryMinutes} minutes
- Can only be used once
- Should only be used by you

If you didn't request this link, please ignore this email.
`,
  htmlVersion: (magicLink: string, expiryMinutes: number) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Login Link</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .container {
      border: 1px solid #e1e1e1;
      border-radius: 5px;
      padding: 20px;
    }
    .button {
      display: inline-block;
      background-color: #4CAF50;
      color: white;
      text-decoration: none;
      padding: 10px 20px;
      border-radius: 5px;
      margin: 20px 0;
    }
    .security-info {
      background-color: #f8f8f8;
      padding: 15px;
      border-radius: 5px;
      margin-top: 20px;
    }
    .footer {
      margin-top: 20px;
      font-size: 12px;
      color: #888;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>Your Secure Login Link</h2>
    <p>Click the button below to log in to your account:</p>
    <a href="${magicLink}" class="button">Login to Your Account</a>

    <p>
      Hello, this is a test email! Hallå, MikroMail has international support for, among others, español, français, português, 中文, 日本語, and Русский!
    </p>

    <div class="security-info">
      <h3>Security Information:</h3>
      <ul>
        <li>This link expires in ${expiryMinutes} minutes</li>
        <li>Can only be used once</li>
        <li>Should only be used by you</li>
      </ul>
    </div>

    <p>If you didn't request this link, please ignore this email.</p>

    <div class="footer">
      <p>This is an automated message, please do not reply to this email.</p>
    </div>
  </div>
</body>
</html>
`
};
