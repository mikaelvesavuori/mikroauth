import { createHash, createHmac } from 'node:crypto';
import type { EmailMessage, EmailProvider } from '../interfaces/index.js';

/**
 * @description AWS SES email provider using the SES v2 HTTP API.
 * @see https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html
 */
export class AWSESProvider implements EmailProvider {
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly region: string;
  private readonly debug: boolean;

  constructor(config: {
    accessKeyId: string;
    secretAccessKey: string;
    region: string;
    debug?: boolean;
  }) {
    if (!config.accessKeyId || !config.secretAccessKey || !config.region) {
      throw new Error(
        'AWSESProvider requires accessKeyId, secretAccessKey, and region'
      );
    }
    this.accessKeyId = config.accessKeyId;
    this.secretAccessKey = config.secretAccessKey;
    this.region = config.region;
    this.debug = config.debug ?? false;
  }

  /**
   * @description Send an email using the AWS SES v2 API.
   */
  public async sendMail(message: EmailMessage): Promise<void> {
    const endpoint = `https://email.${this.region}.amazonaws.com/v2/email/outbound-emails`;

    // Prepare the request body
    const toAddresses = Array.isArray(message.to) ? message.to : [message.to];
    const ccAddresses = message.cc
      ? Array.isArray(message.cc)
        ? message.cc
        : [message.cc]
      : undefined;
    const bccAddresses = message.bcc
      ? Array.isArray(message.bcc)
        ? message.bcc
        : [message.bcc]
      : undefined;

    const body = {
      FromEmailAddress: message.from,
      Destination: {
        ToAddresses: toAddresses,
        ...(ccAddresses && { CcAddresses: ccAddresses }),
        ...(bccAddresses && { BccAddresses: bccAddresses })
      },
      Content: {
        Simple: {
          Subject: {
            Data: message.subject,
            Charset: 'UTF-8'
          },
          Body: {
            ...(message.text && {
              Text: {
                Data: message.text,
                Charset: 'UTF-8'
              }
            }),
            ...(message.html && {
              Html: {
                Data: message.html,
                Charset: 'UTF-8'
              }
            })
          }
        }
      }
    };

    const bodyString = JSON.stringify(body);

    // Create AWS Signature V4
    const date = new Date();
    const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.substring(0, 8);

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      host: `email.${this.region}.amazonaws.com`,
      'x-amz-date': amzDate
    };

    const signedHeaders = Object.keys(headers).sort().join(';');
    const canonicalHeaders = Object.keys(headers)
      .sort()
      .map((key) => `${key}:${headers[key]}`)
      .join('\n');

    // Create canonical request
    const payloadHash = this.sha256(bodyString);
    const canonicalRequest = [
      'POST',
      '/v2/email/outbound-emails',
      '',
      canonicalHeaders,
      '',
      signedHeaders,
      payloadHash
    ].join('\n');

    // Create string to sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${this.region}/ses/aws4_request`;
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      this.sha256(canonicalRequest)
    ].join('\n');

    // Calculate signature
    const signingKey = this.getSignatureKey(
      this.secretAccessKey,
      dateStamp,
      this.region,
      'ses'
    );
    const signature = this.hmacSha256(signingKey, stringToSign).toString('hex');

    // Create authorization header
    const authorizationHeader = `${algorithm} Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    if (this.debug) {
      console.log('[AWSESProvider] Sending email:', {
        endpoint,
        to: toAddresses,
        subject: message.subject
      });
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        ...headers,
        Authorization: authorizationHeader
      },
      body: bodyString
    });

    if (!response.ok) {
      const errorData = await response.text().catch(() => '');
      const error = new Error(
        `AWS SES API error: ${response.status} ${response.statusText}`
      );
      (error as any).status = response.status;
      (error as any).response = errorData;

      if (this.debug) {
        console.error('[AWSESProvider] Error:', error);
      }

      throw error;
    }

    const result = await response.json();

    if (this.debug) {
      console.log('[AWSESProvider] Email sent successfully:', result);
    }
  }

  /**
   * @description Calculate SHA256 hash.
   */
  private sha256(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * @description Calculate HMAC SHA256.
   */
  private hmacSha256(key: Buffer | string, data: string): Buffer {
    return createHmac('sha256', key).update(data).digest();
  }

  /**
   * @description Get signing key for AWS Signature V4.
   */
  private getSignatureKey(
    key: string,
    dateStamp: string,
    regionName: string,
    serviceName: string
  ): Buffer {
    const kDate = this.hmacSha256(`AWS4${key}`, dateStamp);
    const kRegion = this.hmacSha256(kDate, regionName);
    const kService = this.hmacSha256(kRegion, serviceName);
    const kSigning = this.hmacSha256(kService, 'aws4_request');
    return kSigning;
  }
}
