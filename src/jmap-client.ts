import { randomUUID } from 'crypto';
import { FastmailAuth } from './auth.js';

export interface JmapSession {
  apiUrl: string;
  accountId: string;
  capabilities: Record<string, any>;
  downloadUrl?: string;
  uploadUrl?: string;
}

export interface JmapRequest {
  using: string[];
  methodCalls: [string, any, string][];
}

export interface JmapResponse {
  methodResponses: Array<[string, any, string]>;
  sessionState: string;
}

export interface EmailSubmissionResult {
  submissionId: string;
  trackingId: string;
}

export class JmapClient {
  private auth: FastmailAuth;
  private session: JmapSession | null = null;

  constructor(auth: FastmailAuth) {
    this.auth = auth;
  }

  async getSession(): Promise<JmapSession> {
    if (this.session) {
      return this.session;
    }

    const response = await fetch(this.auth.getSessionUrl(), {
      method: 'GET',
      headers: this.auth.getAuthHeaders()
    });

    if (!response.ok) {
      throw new Error(`Failed to get session: ${response.statusText}`);
    }

    const sessionData = await response.json() as any;
    
    this.session = {
      apiUrl: sessionData.apiUrl,
      accountId: Object.keys(sessionData.accounts)[0],
      capabilities: sessionData.capabilities,
      downloadUrl: sessionData.downloadUrl,
      uploadUrl: sessionData.uploadUrl
    };

    return this.session;
  }

  async getUserEmail(): Promise<string> {
    try {
      const identity = await this.getDefaultIdentity();
      return identity?.email || 'user@example.com';
    } catch (error) {
      // Fallback if Identity/get is not available
      return 'user@example.com';
    }
  }

  async makeRequest(request: JmapRequest): Promise<JmapResponse> {
    const session = await this.getSession();
    
    const response = await fetch(session.apiUrl, {
      method: 'POST',
      headers: this.auth.getAuthHeaders(),
      body: JSON.stringify(request)
    });

    if (!response.ok) {
      throw new Error(`JMAP request failed: ${response.statusText}`);
    }

    return await response.json() as JmapResponse;
  }

  async getMailboxes(): Promise<any[]> {
    const session = await this.getSession();

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Mailbox/get', { accountId: session.accountId }, 'mailboxes']
      ]
    };

    const response = await this.makeRequest(request);
    return response.methodResponses[0][1].list;
  }

  async getEmails(mailboxId?: string, limit: number = 20): Promise<any[]> {
    const session = await this.getSession();
    
    const filter = mailboxId ? { inMailbox: mailboxId } : {};
    
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/query', {
          accountId: session.accountId,
          filter,
          sort: [{ property: 'receivedAt', isAscending: false }],
          limit
        }, 'query'],
        ['Email/get', {
          accountId: session.accountId,
          '#ids': { resultOf: 'query', name: 'Email/query', path: '/ids' },
          properties: ['id', 'subject', 'from', 'to', 'receivedAt', 'preview', 'hasAttachment']
        }, 'emails']
      ]
    };

    const response = await this.makeRequest(request);
    return response.methodResponses[1][1].list;
  }

  async getEmailById(id: string): Promise<any> {
    const session = await this.getSession();
    
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/get', {
          accountId: session.accountId,
          ids: [id],
          properties: [
            'id',
            'subject',
            'from',
            'to',
            'cc',
            'bcc',
            'replyTo',
            'receivedAt',
            'textBody',
            'htmlBody',
            'attachments',
            'bodyValues',
            'messageId',
            'header:References:asText'
          ],
          bodyProperties: ['partId', 'blobId', 'type', 'size'],
          fetchTextBodyValues: true,
          fetchHTMLBodyValues: true,
        }, 'email']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notFound && result.notFound.includes(id)) {
      throw new Error(`Email with ID '${id}' not found`);
    }
    
    const email = result.list[0];
    if (!email) {
      throw new Error(`Email with ID '${id}' not found or not accessible`);
    }
    
    return email;
  }

  async getIdentities(): Promise<any[]> {
    const session = await this.getSession();
    
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:submission'],
      methodCalls: [
        ['Identity/get', {
          accountId: session.accountId
        }, 'identities']
      ]
    };

    const response = await this.makeRequest(request);
    return response.methodResponses[0][1].list;
  }

  async getDefaultIdentity(): Promise<any> {
    const identities = await this.getIdentities();
    
    // Find the default identity (usually the one that can't be deleted)
    return identities.find((id: any) => id.mayDelete === false) || identities[0];
  }

  private async resolveIdentity(fromAddress?: string): Promise<any> {
    const identities = await this.getIdentities();
    if (!identities || identities.length === 0) {
      throw new Error('No sending identities found');
    }

    if (fromAddress) {
      const selectedIdentity = identities.find((identity: any) =>
        identity.email.toLowerCase() === fromAddress.toLowerCase()
      );
      if (!selectedIdentity) {
        throw new Error('From address is not verified for sending. Choose one of your verified identities.');
      }
      return selectedIdentity;
    }

    return identities.find((identity: any) => identity.mayDelete === false) || identities[0];
  }

  private async getMailboxByRole(role: string, nameHint: string): Promise<any> {
    const mailboxes = await this.getMailboxes();
    const mailbox = mailboxes.find(mb => mb.role === role) || mailboxes.find(mb => mb.name.toLowerCase().includes(nameHint));
    if (!mailbox) {
      throw new Error(`Could not find ${role} mailbox`);
    }
    return mailbox;
  }

  private buildMailboxIds(mailboxId: string): Record<string, boolean> {
    const mailboxIds: Record<string, boolean> = {};
    mailboxIds[mailboxId] = true;
    return mailboxIds;
  }

  private buildEmailObject(email: {
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject: string;
    textBody?: string;
    htmlBody?: string;
    mailboxId?: string;
  }, fromEmail: string, mailboxId: string): any {
    return {
      mailboxIds: this.buildMailboxIds(mailboxId),
      keywords: { $draft: true },
      from: [{ email: fromEmail }],
      to: email.to.map(addr => ({ email: addr })),
      cc: email.cc?.map(addr => ({ email: addr })) || [],
      bcc: email.bcc?.map(addr => ({ email: addr })) || [],
      subject: email.subject,
      textBody: email.textBody !== undefined ? [{ partId: 'text', type: 'text/plain' }] : undefined,
      htmlBody: email.htmlBody !== undefined ? [{ partId: 'html', type: 'text/html' }] : undefined,
      bodyValues: {
        ...(email.textBody !== undefined && { text: { value: email.textBody } }),
        ...(email.htmlBody !== undefined && { html: { value: email.htmlBody } })
      }
    };
  }

  private getBodyValue(email: any, bodyPart: any[] | undefined): string | undefined {
    const partId = bodyPart?.[0]?.partId;
    if (!partId) {
      return undefined;
    }
    const value = email.bodyValues?.[partId]?.value;
    return typeof value === 'string' ? value : undefined;
  }

  private normalizeSubjectPrefix(subject: string, prefix: string): string {
    const escapedPrefix = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const prefixedSubjectRegex = new RegExp(`^\\s*${escapedPrefix}\\s*:`, 'i');
    if (prefixedSubjectRegex.test(subject)) {
      return subject;
    }
    return `${prefix}: ${subject}`;
  }

  private dedupeEmailAddresses(addresses: string[]): string[] {
    const seen = new Set<string>();
    const deduped: string[] = [];

    for (const address of addresses) {
      const normalized = address.trim().toLowerCase();
      if (!normalized || seen.has(normalized)) {
        continue;
      }
      seen.add(normalized);
      deduped.push(address.trim());
    }

    return deduped;
  }

  private escapeHtml(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  private stripHtml(value: string): string {
    return value.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  private formatAddress(address: any): string {
    if (!address || !address.email) {
      return 'unknown sender';
    }
    return address.name ? `${address.name} <${address.email}>` : address.email;
  }

  private normalizeMessageId(messageId: string): string {
    const trimmed = messageId.trim();
    if (!trimmed) {
      return '';
    }
    if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
      return trimmed;
    }
    return `<${trimmed}>`;
  }

  private async createDraftEmail(emailObject: any): Promise<string> {
    const session = await this.getSession();
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          create: { draft: emailObject }
        }, 'createDraft']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    if (result.notCreated && result.notCreated.draft) {
      throw new Error('Failed to save draft. Please check inputs and try again.');
    }

    return result.created?.draft?.id || 'unknown';
  }

  private getTrackingPixelUrlBase(): string | null {
    const trackingPixelUrl = process.env.TRACKING_PIXEL_URL?.trim();
    if (!trackingPixelUrl) {
      return null;
    }
    return trackingPixelUrl.replace(/\/+$/, '');
  }

  private injectTrackingPixel(htmlBody: string, trackingId: string): string {
    const trackingPixelUrlBase = this.getTrackingPixelUrlBase();
    if (!trackingPixelUrlBase) {
      return htmlBody;
    }

    const pixelTag = `<img src="${trackingPixelUrlBase}/pixel/${trackingId}.gif" width="1" height="1" style="display:none" />`;
    if (/<\/body>/i.test(htmlBody)) {
      return htmlBody.replace(/<\/body>/i, `${pixelTag}</body>`);
    }

    return `${htmlBody}${pixelTag}`;
  }

  private async updateDraftHtmlForTracking(draftEmailId: string, draftEmail: any, trackingId: string): Promise<void> {
    const existingHtmlBody = this.getBodyValue(draftEmail, draftEmail.htmlBody);
    if (existingHtmlBody === undefined) {
      return;
    }

    const trackedHtmlBody = this.injectTrackingPixel(existingHtmlBody, trackingId);
    if (trackedHtmlBody === existingHtmlBody) {
      return;
    }

    const existingTextBody = this.getBodyValue(draftEmail, draftEmail.textBody);
    const bodyValues: Record<string, { value: string }> = {
      html: { value: trackedHtmlBody }
    };
    if (existingTextBody !== undefined) {
      bodyValues.text = { value: existingTextBody };
    }

    const session = await this.getSession();
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: {
            [draftEmailId]: {
              textBody: existingTextBody !== undefined ? [{ partId: 'text', type: 'text/plain' }] : [],
              htmlBody: [{ partId: 'html', type: 'text/html' }],
              bodyValues
            }
          }
        }, 'updateDraftForTracking']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    if (result.notUpdated && result.notUpdated[draftEmailId]) {
      throw new Error('Failed to add tracking pixel to draft before sending.');
    }
  }

  async sendEmail(email: {
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject: string;
    textBody?: string;
    htmlBody?: string;
    from?: string;
    mailboxId?: string;
  }): Promise<EmailSubmissionResult> {
    const session = await this.getSession();
    const selectedIdentity = await this.resolveIdentity(email.from);
    const fromEmail = selectedIdentity.email;

    const draftsMailbox = await this.getMailboxByRole('drafts', 'draft');
    const sentMailbox = await this.getMailboxByRole('sent', 'sent');

    // Use provided mailboxId or default to drafts for initial creation
    const initialMailboxId = email.mailboxId || draftsMailbox.id;

    // Ensure we have at least one body type
    if (!email.textBody && !email.htmlBody) {
      throw new Error('Either textBody or htmlBody must be provided');
    }

    const sentMailboxIds = this.buildMailboxIds(sentMailbox.id);
    
    const envelopeRecipients = [
      ...email.to,
      ...(email.cc || []),
      ...(email.bcc || [])
    ];

    const trackingId = randomUUID();
    const trackedEmail = {
      ...email,
      htmlBody: email.htmlBody !== undefined ? this.injectTrackingPixel(email.htmlBody, trackingId) : email.htmlBody
    };
    const emailObject = this.buildEmailObject(trackedEmail, fromEmail, initialMailboxId);

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:submission'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          create: { draft: emailObject }
        }, 'createEmail'],
        ['EmailSubmission/set', {
          accountId: session.accountId,
          create: {
            submission: {
              emailId: '#draft',
              identityId: selectedIdentity.id,
              envelope: {
                mailFrom: { email: fromEmail },
                rcptTo: envelopeRecipients.map(addr => ({ email: addr }))
              }
            }
          },
          onSuccessUpdateEmail: {
            '#submission': {
              mailboxIds: sentMailboxIds,
              keywords: { $seen: true }
            }
          }
        }, 'submitEmail']
      ]
    };

    const response = await this.makeRequest(request);
    
    // Check if email creation was successful
    const emailResult = response.methodResponses[0][1];
    if (emailResult.notCreated && emailResult.notCreated.draft) {
      throw new Error('Failed to create email. Please check inputs and try again.');
    }
    
    // Check if email submission was successful
    const submissionResult = response.methodResponses[1][1];
    if (submissionResult.notCreated && submissionResult.notCreated.submission) {
      throw new Error('Failed to submit email. Please try again later.');
    }
    
    return {
      submissionId: submissionResult.created?.submission?.id || 'unknown',
      trackingId
    };
  }

  async saveDraft(email: {
    to: string[];
    cc?: string[];
    bcc?: string[];
    subject: string;
    textBody?: string;
    htmlBody?: string;
    from?: string;
    mailboxId?: string;
  }): Promise<string> {
    const selectedIdentity = await this.resolveIdentity(email.from);
    const draftsMailbox = await this.getMailboxByRole('drafts', 'draft');

    if (!email.textBody && !email.htmlBody) {
      throw new Error('Either textBody or htmlBody must be provided');
    }

    const initialMailboxId = email.mailboxId || draftsMailbox.id;
    const emailObject = this.buildEmailObject(email, selectedIdentity.email, initialMailboxId);
    return this.createDraftEmail(emailObject);
  }

  async sendDraft(draftEmailId: string): Promise<EmailSubmissionResult> {
    const session = await this.getSession();
    const draftEmail = await this.getEmailById(draftEmailId);
    const sentMailbox = await this.getMailboxByRole('sent', 'sent');
    const trackingId = randomUUID();

    await this.updateDraftHtmlForTracking(draftEmailId, draftEmail, trackingId);

    const toRecipients = (draftEmail.to || []).map((addr: any) => addr.email).filter(Boolean);
    const ccRecipients = (draftEmail.cc || []).map((addr: any) => addr.email).filter(Boolean);
    const bccRecipients = (draftEmail.bcc || []).map((addr: any) => addr.email).filter(Boolean);
    const envelopeRecipients = [...toRecipients, ...ccRecipients, ...bccRecipients];

    if (envelopeRecipients.length === 0) {
      throw new Error('Draft must have at least one recipient before sending.');
    }

    const fromAddress = draftEmail.from?.[0]?.email;
    const selectedIdentity = await this.resolveIdentity(fromAddress);
    const sentMailboxIds = this.buildMailboxIds(sentMailbox.id);

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:submission'],
      methodCalls: [
        ['EmailSubmission/set', {
          accountId: session.accountId,
          create: {
            submission: {
              emailId: draftEmailId,
              identityId: selectedIdentity.id,
              envelope: {
                mailFrom: { email: selectedIdentity.email },
                rcptTo: envelopeRecipients.map((addr: string) => ({ email: addr }))
              }
            }
          },
          onSuccessUpdateEmail: {
            '#submission': {
              mailboxIds: sentMailboxIds,
              keywords: { $seen: true }
            }
          }
        }, 'submitDraft']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];

    if (result.notCreated && result.notCreated.submission) {
      throw new Error('Failed to submit draft. Please try again later.');
    }

    return {
      submissionId: result.created?.submission?.id || 'unknown',
      trackingId
    };
  }

  async listDrafts(limit: number = 20): Promise<any[]> {
    const session = await this.getSession();
    const draftsMailbox = await this.getMailboxByRole('drafts', 'draft');

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/query', {
          accountId: session.accountId,
          filter: { inMailbox: draftsMailbox.id },
          sort: [{ property: 'receivedAt', isAscending: false }],
          limit: Math.min(limit, 50)
        }, 'queryDrafts'],
        ['Email/get', {
          accountId: session.accountId,
          '#ids': { resultOf: 'queryDrafts', name: 'Email/query', path: '/ids' },
          properties: ['id', 'subject', 'from', 'to', 'cc', 'bcc', 'receivedAt', 'preview', 'hasAttachment', 'keywords']
        }, 'drafts']
      ]
    };

    const response = await this.makeRequest(request);
    return response.methodResponses[1][1].list;
  }

  async updateDraft(draftEmailId: string, updates: {
    to?: string[];
    cc?: string[];
    bcc?: string[];
    subject?: string;
    textBody?: string;
    htmlBody?: string;
    from?: string;
  }): Promise<void> {
    const session = await this.getSession();

    const hasAnyUpdate = (
      updates.to !== undefined ||
      updates.cc !== undefined ||
      updates.bcc !== undefined ||
      updates.subject !== undefined ||
      updates.textBody !== undefined ||
      updates.htmlBody !== undefined ||
      updates.from !== undefined
    );

    if (!hasAnyUpdate) {
      throw new Error('At least one draft field must be provided for update.');
    }

    const existingDraft = await this.getEmailById(draftEmailId);
    const patch: Record<string, any> = {};

    if (updates.to !== undefined) {
      patch.to = updates.to.map(addr => ({ email: addr }));
    }
    if (updates.cc !== undefined) {
      patch.cc = updates.cc.map(addr => ({ email: addr }));
    }
    if (updates.bcc !== undefined) {
      patch.bcc = updates.bcc.map(addr => ({ email: addr }));
    }
    if (updates.subject !== undefined) {
      patch.subject = updates.subject;
    }
    if (updates.from !== undefined) {
      const selectedIdentity = await this.resolveIdentity(updates.from);
      patch.from = [{ email: selectedIdentity.email }];
    }

    if (updates.textBody !== undefined || updates.htmlBody !== undefined) {
      const existingTextBody = this.getBodyValue(existingDraft, existingDraft.textBody);
      const existingHtmlBody = this.getBodyValue(existingDraft, existingDraft.htmlBody);

      const nextTextBody = updates.textBody !== undefined ? updates.textBody : existingTextBody;
      const nextHtmlBody = updates.htmlBody !== undefined ? updates.htmlBody : existingHtmlBody;

      if (nextTextBody === undefined && nextHtmlBody === undefined) {
        throw new Error('Draft must include at least one of textBody or htmlBody.');
      }

      patch.textBody = nextTextBody !== undefined ? [{ partId: 'text', type: 'text/plain' }] : [];
      patch.htmlBody = nextHtmlBody !== undefined ? [{ partId: 'html', type: 'text/html' }] : [];
      patch.bodyValues = {
        ...(nextTextBody !== undefined && { text: { value: nextTextBody } }),
        ...(nextHtmlBody !== undefined && { html: { value: nextHtmlBody } })
      };
    }

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: {
            [draftEmailId]: patch
          }
        }, 'updateDraft']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    if (result.notUpdated && result.notUpdated[draftEmailId]) {
      throw new Error('Failed to update draft.');
    }
  }

  async deleteDraft(draftEmailId: string): Promise<void> {
    const session = await this.getSession();

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          destroy: [draftEmailId]
        }, 'deleteDraft']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    if (result.notDestroyed && result.notDestroyed[draftEmailId]) {
      throw new Error('Failed to delete draft.');
    }
  }

  async replyToEmail(params: {
    emailId: string;
    textBody?: string;
    htmlBody?: string;
    replyAll?: boolean;
  }): Promise<string> {
    const { emailId, textBody, htmlBody, replyAll = false } = params;
    if (!textBody && !htmlBody) {
      throw new Error('Reply body is required as textBody and/or htmlBody.');
    }

    const originalEmail = await this.getEmailById(emailId);
    const selectedIdentity = await this.resolveIdentity();
    const draftsMailbox = await this.getMailboxByRole('drafts', 'draft');

    const identityEmails = new Set(
      (await this.getIdentities()).map((identity: any) => identity.email.toLowerCase())
    );

    const replyTargetAddresses = (
      originalEmail.replyTo?.length ? originalEmail.replyTo : originalEmail.from
    ) || [];

    const baseToRecipients = replyTargetAddresses
      .map((address: any) => address.email)
      .filter((address: string | undefined): address is string => Boolean(address));

    let toRecipients = this.dedupeEmailAddresses(baseToRecipients);
    let ccRecipients: string[] = [];

    if (replyAll) {
      const originalTo = (originalEmail.to || [])
        .map((address: any) => address.email)
        .filter((address: string | undefined): address is string => Boolean(address));
      const originalCc = (originalEmail.cc || [])
        .map((address: any) => address.email)
        .filter((address: string | undefined): address is string => Boolean(address));

      const filteredTo = originalTo.filter((address: string) => !identityEmails.has(address.toLowerCase()));
      toRecipients = this.dedupeEmailAddresses([...toRecipients, ...filteredTo]);

      ccRecipients = this.dedupeEmailAddresses(
        originalCc.filter((address: string) =>
          !identityEmails.has(address.toLowerCase()) &&
          !toRecipients.some(toAddress => toAddress.toLowerCase() === address.toLowerCase())
        )
      );
    }

    if (toRecipients.length === 0 && originalEmail.from?.[0]?.email) {
      toRecipients = [originalEmail.from[0].email];
    }
    if (toRecipients.length === 0) {
      throw new Error('Could not determine recipient for reply.');
    }

    const originalSubject = originalEmail.subject || '(no subject)';
    const replySubject = this.normalizeSubjectPrefix(originalSubject, 'Re');
    const originalSender = this.formatAddress(originalEmail.from?.[0]);
    const originalDate = originalEmail.receivedAt ? new Date(originalEmail.receivedAt).toUTCString() : 'an unknown date';

    const originalTextBody =
      this.getBodyValue(originalEmail, originalEmail.textBody) ||
      this.stripHtml(this.getBodyValue(originalEmail, originalEmail.htmlBody) || '');
    const originalHtmlBody = this.getBodyValue(originalEmail, originalEmail.htmlBody);

    const quotedTextBody = originalTextBody
      ? originalTextBody.split(/\r?\n/).map((line: string) => `> ${line}`).join('\n')
      : '> (no original message content)';
    const composedTextBody = [
      textBody?.trim() || '',
      '',
      `On ${originalDate}, ${originalSender} wrote:`,
      quotedTextBody
    ].join('\n').trim();

    let composedHtmlBody: string | undefined;
    const htmlIntro = htmlBody !== undefined
      ? htmlBody
      : (textBody ? `<p>${this.escapeHtml(textBody).replace(/\n/g, '<br />')}</p>` : undefined);

    if (htmlIntro !== undefined || originalHtmlBody !== undefined) {
      const quotedHtml = originalHtmlBody !== undefined
        ? originalHtmlBody
        : `<pre>${this.escapeHtml(originalTextBody || '(no original message content)')}</pre>`;
      composedHtmlBody = `${htmlIntro || ''}<p>${this.escapeHtml(`On ${originalDate}, ${originalSender} wrote:`)}</p><blockquote>${quotedHtml}</blockquote>`;
    }

    const messageIds = Array.isArray(originalEmail.messageId)
      ? originalEmail.messageId
      : (typeof originalEmail.messageId === 'string' ? [originalEmail.messageId] : []);
    const normalizedMessageId = typeof messageIds[0] === 'string'
      ? this.normalizeMessageId(messageIds[0])
      : '';
    const existingReferences = typeof originalEmail['header:References:asText'] === 'string'
      ? originalEmail['header:References:asText'].trim()
      : '';

    const headers: Array<{ name: string; value: string }> = [];
    if (normalizedMessageId) {
      headers.push({ name: 'In-Reply-To', value: normalizedMessageId });
    }

    const referencesValue = [existingReferences, normalizedMessageId].filter(Boolean).join(' ').trim();
    if (referencesValue) {
      headers.push({ name: 'References', value: referencesValue });
    }

    const replyDraftObject = this.buildEmailObject({
      to: toRecipients,
      cc: ccRecipients,
      subject: replySubject,
      textBody: composedTextBody || undefined,
      htmlBody: composedHtmlBody
    }, selectedIdentity.email, draftsMailbox.id);

    if (headers.length > 0) {
      replyDraftObject.headers = headers;
    }

    return this.createDraftEmail(replyDraftObject);
  }

  async forwardEmail(params: {
    emailId: string;
    to: string[];
    body?: string;
  }): Promise<string> {
    const { emailId, to, body } = params;
    const dedupedTo = this.dedupeEmailAddresses(to);
    if (dedupedTo.length === 0) {
      throw new Error('Forward requires at least one recipient.');
    }

    const originalEmail = await this.getEmailById(emailId);
    const selectedIdentity = await this.resolveIdentity();
    const draftsMailbox = await this.getMailboxByRole('drafts', 'draft');

    const originalSubject = originalEmail.subject || '(no subject)';
    const forwardSubject = this.normalizeSubjectPrefix(originalSubject, 'Fwd');
    const originalSender = this.formatAddress(originalEmail.from?.[0]);
    const originalRecipients = (originalEmail.to || []).map((address: any) => this.formatAddress(address)).join(', ') || '(unknown)';
    const originalDate = originalEmail.receivedAt ? new Date(originalEmail.receivedAt).toUTCString() : 'an unknown date';

    const originalTextBody =
      this.getBodyValue(originalEmail, originalEmail.textBody) ||
      this.stripHtml(this.getBodyValue(originalEmail, originalEmail.htmlBody) || '');
    const originalHtmlBody = this.getBodyValue(originalEmail, originalEmail.htmlBody);

    const forwardedHeaderText = [
      '---------- Forwarded message ----------',
      `From: ${originalSender}`,
      `Date: ${originalDate}`,
      `Subject: ${originalSubject}`,
      `To: ${originalRecipients}`
    ].join('\n');

    const composedTextBody = [
      body?.trim() || '',
      body ? '' : '',
      forwardedHeaderText,
      '',
      originalTextBody || '(no original message content)'
    ].join('\n').trim();

    let composedHtmlBody: string | undefined;
    if (originalHtmlBody !== undefined || body !== undefined) {
      const introHtml = body ? `<p>${this.escapeHtml(body).replace(/\n/g, '<br />')}</p>` : '';
      const forwardedHeaderHtml = `<pre>${this.escapeHtml(forwardedHeaderText)}</pre>`;
      const forwardedContentHtml = originalHtmlBody !== undefined
        ? `<blockquote>${originalHtmlBody}</blockquote>`
        : `<pre>${this.escapeHtml(originalTextBody || '(no original message content)')}</pre>`;
      composedHtmlBody = `${introHtml}${forwardedHeaderHtml}${forwardedContentHtml}`;
    }

    const forwardedAttachments = (originalEmail.attachments || [])
      .map((attachment: any) => ({
        blobId: attachment.blobId,
        type: attachment.type,
        name: attachment.name,
        size: attachment.size,
        cid: attachment.cid,
        disposition: attachment.disposition
      }))
      .filter((attachment: any) => attachment.blobId && attachment.type);

    const forwardDraftObject = this.buildEmailObject({
      to: dedupedTo,
      subject: forwardSubject,
      textBody: composedTextBody || undefined,
      htmlBody: composedHtmlBody
    }, selectedIdentity.email, draftsMailbox.id);

    if (forwardedAttachments.length > 0) {
      forwardDraftObject.attachments = forwardedAttachments;
    }

    return this.createDraftEmail(forwardDraftObject);
  }

  async getRecentEmails(limit: number = 10, mailboxName: string = 'inbox'): Promise<any[]> {
    const session = await this.getSession();
    
    // Find the specified mailbox (default to inbox)
    const mailboxes = await this.getMailboxes();
    const targetMailbox = mailboxes.find(mb => 
      mb.role === mailboxName.toLowerCase() || 
      mb.name.toLowerCase().includes(mailboxName.toLowerCase())
    );
    
    if (!targetMailbox) {
      throw new Error(`Could not find mailbox: ${mailboxName}`);
    }

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/query', {
          accountId: session.accountId,
          filter: { inMailbox: targetMailbox.id },
          sort: [{ property: 'receivedAt', isAscending: false }],
          limit: Math.min(limit, 50)
        }, 'query'],
        ['Email/get', {
          accountId: session.accountId,
          '#ids': { resultOf: 'query', name: 'Email/query', path: '/ids' },
          properties: ['id', 'subject', 'from', 'to', 'receivedAt', 'preview', 'hasAttachment', 'keywords']
        }, 'emails']
      ]
    };

    const response = await this.makeRequest(request);
    return response.methodResponses[1][1].list;
  }

  async markEmailRead(emailId: string, read: boolean = true): Promise<void> {
    const session = await this.getSession();
    
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: {
            [emailId]: {
              'keywords/$seen': read ? true : null
            }
          }
        }, 'updateEmail']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notUpdated && result.notUpdated[emailId]) {
      throw new Error(`Failed to mark email as ${read ? 'read' : 'unread'}.`);
    }
  }

  async deleteEmail(emailId: string): Promise<void> {
    const session = await this.getSession();
    
    // Find the trash mailbox
    const mailboxes = await this.getMailboxes();
    const trashMailbox = mailboxes.find(mb => mb.role === 'trash') || mailboxes.find(mb => mb.name.toLowerCase().includes('trash'));
    
    if (!trashMailbox) {
      throw new Error('Could not find Trash mailbox');
    }

    const trashMailboxIds: Record<string, boolean> = {};
    trashMailboxIds[trashMailbox.id] = true;

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: {
            [emailId]: {
              mailboxIds: trashMailboxIds
            }
          }
        }, 'moveToTrash']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notUpdated && result.notUpdated[emailId]) {
      throw new Error('Failed to delete email.');
    }
  }

  async moveEmail(emailId: string, targetMailboxId: string): Promise<void> {
    const session = await this.getSession();

    const targetMailboxIds: Record<string, boolean> = {};
    targetMailboxIds[targetMailboxId] = true;

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: {
            [emailId]: {
              mailboxIds: targetMailboxIds
            }
          }
        }, 'moveEmail']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notUpdated && result.notUpdated[emailId]) {
      throw new Error('Failed to move email.');
    }
  }

  async getEmailAttachments(emailId: string): Promise<any[]> {
    const session = await this.getSession();

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/get', {
          accountId: session.accountId,
          ids: [emailId],
          properties: ['attachments']
        }, 'getAttachments']
      ]
    };

    const response = await this.makeRequest(request);
    const email = response.methodResponses[0][1].list[0];
    return email?.attachments || [];
  }

  async downloadAttachment(emailId: string, attachmentId: string): Promise<string> {
    const session = await this.getSession();

    // Get the email with full attachment details
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/get', {
          accountId: session.accountId,
          ids: [emailId],
          properties: ['attachments', 'bodyValues'],
          bodyProperties: ['partId', 'blobId', 'size', 'name', 'type']
        }, 'getEmail']
      ]
    };

    const response = await this.makeRequest(request);
    const email = response.methodResponses[0][1].list[0];
    
    if (!email) {
      throw new Error('Email not found');
    }

    // Find attachment by partId or by index
    let attachment = email.attachments?.find((att: any) => 
      att.partId === attachmentId || att.blobId === attachmentId
    );

    // If not found, try by array index
    if (!attachment && !isNaN(parseInt(attachmentId))) {
      const index = parseInt(attachmentId);
      attachment = email.attachments?.[index];
    }
    
    if (!attachment) {
      throw new Error('Attachment not found.');
    }

    // Get the download URL from session
    const downloadUrl = session.downloadUrl;
    if (!downloadUrl) {
      throw new Error('Download capability not available in session');
    }

    // Build download URL
    const url = downloadUrl
      .replace('{accountId}', session.accountId)
      .replace('{blobId}', attachment.blobId)
      .replace('{type}', encodeURIComponent(attachment.type || 'application/octet-stream'))
      .replace('{name}', encodeURIComponent(attachment.name || 'attachment'));

    return url;
  }

  async advancedSearch(filters: {
    query?: string;
    from?: string;
    to?: string;
    subject?: string;
    hasAttachment?: boolean;
    isUnread?: boolean;
    mailboxId?: string;
    after?: string;
    before?: string;
    limit?: number;
  }): Promise<any[]> {
    const session = await this.getSession();
    
    // Build JMAP filter object
    const filter: any = {};
    
    if (filters.query) filter.text = filters.query;
    if (filters.from) filter.from = filters.from;
    if (filters.to) filter.to = filters.to;
    if (filters.subject) filter.subject = filters.subject;
    if (filters.hasAttachment !== undefined) filter.hasAttachment = filters.hasAttachment;
    if (filters.isUnread !== undefined) filter.hasKeyword = filters.isUnread ? undefined : '$seen';
    if (filters.mailboxId) filter.inMailbox = filters.mailboxId;
    if (filters.after) filter.after = filters.after;
    if (filters.before) filter.before = filters.before;

    // If unread filter is specifically true, we need to check for absence of $seen
    if (filters.isUnread === true) {
      filter.notKeyword = '$seen';
      delete filter.hasKeyword;
    }

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/query', {
          accountId: session.accountId,
          filter,
          sort: [{ property: 'receivedAt', isAscending: false }],
          limit: Math.min(filters.limit || 50, 100)
        }, 'query'],
        ['Email/get', {
          accountId: session.accountId,
          '#ids': { resultOf: 'query', name: 'Email/query', path: '/ids' },
          properties: ['id', 'subject', 'from', 'to', 'cc', 'receivedAt', 'preview', 'hasAttachment', 'keywords', 'threadId']
        }, 'emails']
      ]
    };

    const response = await this.makeRequest(request);
    return response.methodResponses[1][1].list;
  }

  async getThread(threadId: string): Promise<any[]> {
    const session = await this.getSession();

    // First, check if threadId is actually an email ID and resolve the thread
    let actualThreadId = threadId;
    
    // Try to get the email first to see if we need to resolve thread ID
    try {
      const emailRequest: JmapRequest = {
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
        methodCalls: [
          ['Email/get', {
            accountId: session.accountId,
            ids: [threadId],
            properties: ['threadId']
          }, 'checkEmail']
        ]
      };
      
      const emailResponse = await this.makeRequest(emailRequest);
      const email = emailResponse.methodResponses[0][1].list[0];
      
      if (email && email.threadId) {
        actualThreadId = email.threadId;
      }
    } catch (error) {
      // If email lookup fails, assume threadId is correct
    }

    // Use Thread/get with the resolved thread ID
    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Thread/get', {
          accountId: session.accountId,
          ids: [actualThreadId]
        }, 'getThread'],
        ['Email/get', {
          accountId: session.accountId,
          '#ids': { resultOf: 'getThread', name: 'Thread/get', path: '/list/*/emailIds' },
          properties: ['id', 'subject', 'from', 'to', 'cc', 'receivedAt', 'preview', 'hasAttachment', 'keywords', 'threadId']
        }, 'emails']
      ]
    };

    const response = await this.makeRequest(request);
    const threadResult = response.methodResponses[0][1];
    
    // Check if thread was found
    if (threadResult.notFound && threadResult.notFound.includes(actualThreadId)) {
      throw new Error(`Thread with ID '${actualThreadId}' not found`);
    }
    
    return response.methodResponses[1][1].list;
  }

  async getMailboxStats(mailboxId?: string): Promise<any> {
    const session = await this.getSession();
    
    if (mailboxId) {
      // Get stats for specific mailbox
      const request: JmapRequest = {
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
        methodCalls: [
          ['Mailbox/get', {
            accountId: session.accountId,
            ids: [mailboxId],
            properties: ['id', 'name', 'role', 'totalEmails', 'unreadEmails', 'totalThreads', 'unreadThreads']
          }, 'mailbox']
        ]
      };

      const response = await this.makeRequest(request);
      return response.methodResponses[0][1].list[0];
    } else {
      // Get stats for all mailboxes
      const mailboxes = await this.getMailboxes();
      return mailboxes.map(mb => ({
        id: mb.id,
        name: mb.name,
        role: mb.role,
        totalEmails: mb.totalEmails || 0,
        unreadEmails: mb.unreadEmails || 0,
        totalThreads: mb.totalThreads || 0,
        unreadThreads: mb.unreadThreads || 0
      }));
    }
  }

  async getAccountSummary(): Promise<any> {
    const session = await this.getSession();
    const mailboxes = await this.getMailboxes();
    const identities = await this.getIdentities();

    // Calculate totals
    const totals = mailboxes.reduce((acc, mb) => ({
      totalEmails: acc.totalEmails + (mb.totalEmails || 0),
      unreadEmails: acc.unreadEmails + (mb.unreadEmails || 0),
      totalThreads: acc.totalThreads + (mb.totalThreads || 0),
      unreadThreads: acc.unreadThreads + (mb.unreadThreads || 0)
    }), { totalEmails: 0, unreadEmails: 0, totalThreads: 0, unreadThreads: 0 });

    return {
      accountId: session.accountId,
      mailboxCount: mailboxes.length,
      identityCount: identities.length,
      ...totals,
      mailboxes: mailboxes.map(mb => ({
        id: mb.id,
        name: mb.name,
        role: mb.role,
        totalEmails: mb.totalEmails || 0,
        unreadEmails: mb.unreadEmails || 0
      }))
    };
  }

  async bulkMarkRead(emailIds: string[], read: boolean = true): Promise<void> {
    const session = await this.getSession();

    const updates: Record<string, any> = {};
    
    emailIds.forEach(id => {
      updates[id] = { 'keywords/$seen': read ? true : null };
    });

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: updates
        }, 'bulkUpdate']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notUpdated && Object.keys(result.notUpdated).length > 0) {
      throw new Error('Failed to update some emails.');
    }
  }

  async bulkMove(emailIds: string[], targetMailboxId: string): Promise<void> {
    const session = await this.getSession();

    const targetMailboxIds: Record<string, boolean> = {};
    targetMailboxIds[targetMailboxId] = true;

    const updates: Record<string, any> = {};
    emailIds.forEach(id => {
      updates[id] = { mailboxIds: targetMailboxIds };
    });

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: updates
        }, 'bulkMove']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notUpdated && Object.keys(result.notUpdated).length > 0) {
      throw new Error('Failed to move some emails.');
    }
  }

  async bulkDelete(emailIds: string[]): Promise<void> {
    const session = await this.getSession();
    
    // Find the trash mailbox
    const mailboxes = await this.getMailboxes();
    const trashMailbox = mailboxes.find(mb => mb.role === 'trash') || mailboxes.find(mb => mb.name.toLowerCase().includes('trash'));
    
    if (!trashMailbox) {
      throw new Error('Could not find Trash mailbox');
    }

    const trashMailboxIds: Record<string, boolean> = {};
    trashMailboxIds[trashMailbox.id] = true;

    const updates: Record<string, any> = {};
    emailIds.forEach(id => {
      updates[id] = { mailboxIds: trashMailboxIds };
    });

    const request: JmapRequest = {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [
        ['Email/set', {
          accountId: session.accountId,
          update: updates
        }, 'bulkDelete']
      ]
    };

    const response = await this.makeRequest(request);
    const result = response.methodResponses[0][1];
    
    if (result.notUpdated && Object.keys(result.notUpdated).length > 0) {
      throw new Error('Failed to delete some emails.');
    }
  }
}
