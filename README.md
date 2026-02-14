# fastmail-mcp

A production-focused Fastmail MCP server for email, contacts, and calendar automation via JMAP.

This repository is a fork of [`MadLlama25/fastmail-mcp`](https://github.com/MadLlama25/fastmail-mcp), with reliability fixes and workflow enhancements for real-world agent usage.

## What This Fork Adds

- Fixed CC/BCC envelope handling so all recipients are correctly delivered
- Fixed `mark_email_read` behavior to patch only `$seen` instead of overwriting all keywords
- Added full draft lifecycle tools: `save_draft`, `send_draft`, `list_drafts`, `update_draft`, `delete_draft`
- Added optional tracking pixel injection via `TRACKING_PIXEL_URL`
- Added `reply_to_email` and `forward_email` with threading-aware headers (`In-Reply-To`, `References`)
- Improved type safety across core JMAP client paths

## Tooling Surface (35 Tools)

### Email Core (15)

- `list_mailboxes`
- `list_emails`
- `get_email`
- `send_email`
- `search_emails`
- `get_recent_emails`
- `mark_email_read`
- `delete_email`
- `move_email`
- `get_email_attachments`
- `download_attachment`
- `advanced_search`
- `get_thread`
- `list_identities`
- `get_mailbox_stats`

### Drafts, Reply, and Forward (7)

- `save_draft`
- `send_draft`
- `list_drafts`
- `update_draft`
- `delete_draft`
- `reply_to_email`
- `forward_email`

### Bulk and Diagnostics (5)

- `bulk_mark_read`
- `bulk_move`
- `bulk_delete`
- `check_function_availability`
- `test_bulk_operations`

### Contacts and Calendar (8)

- `list_contacts`
- `get_contact`
- `search_contacts`
- `list_calendars`
- `list_calendar_events`
- `get_calendar_event`
- `create_calendar_event`
- `get_account_summary`

## Installation

### 1) npm (from source)

```bash
git clone https://github.com/mzogithub/fastmail-mcp.git
cd fastmail-mcp
npm install
npm run build
npm start
```

### 2) npx (run directly from GitHub)

```bash
FASTMAIL_API_TOKEN="your_token" \
FASTMAIL_BASE_URL="https://api.fastmail.com" \
npx --yes github:mzogithub/fastmail-mcp fastmail-mcp
```

### 3) DXT (Claude Desktop Extension)

```bash
npm install
npm run build
npx dxt pack
```

Then open the generated `fastmail-mcp.dxt` file in Claude Desktop.

## Environment Variables

- `FASTMAIL_API_TOKEN` (required): Fastmail API token
- `FASTMAIL_BASE_URL` (optional): defaults to `https://api.fastmail.com`
- `TRACKING_PIXEL_URL` (optional): enables pixel injection for HTML sends/draft sends

Example:

```bash
export FASTMAIL_API_TOKEN="fm_..."
export FASTMAIL_BASE_URL="https://api.fastmail.com"
export TRACKING_PIXEL_URL="https://your-tracker.example.com"
```

## Usage Examples

### Save + Send Draft

```json
{
  "tool": "save_draft",
  "arguments": {
    "to": ["team@example.com"],
    "subject": "Draft: Q1 status",
    "textBody": "Here is the current draft update..."
  }
}
```

```json
{
  "tool": "send_draft",
  "arguments": {
    "draftEmailId": "email-id-from-save_draft"
  }
}
```

### Reply with Proper Threading

```json
{
  "tool": "reply_to_email",
  "arguments": {
    "emailId": "original-email-id",
    "replyAll": true,
    "body": {
      "text": "Thanks all, sharing the latest update below."
    }
  }
}
```

### Forward an Email

```json
{
  "tool": "forward_email",
  "arguments": {
    "emailId": "source-email-id",
    "to": ["external@example.com"],
    "body": "Forwarding this for your review."
  }
}
```

### Tracking Pixel Injection

When `TRACKING_PIXEL_URL` is set and an email contains HTML, a tracking pixel is appended automatically using a generated tracking ID:

```txt
<TRACKING_PIXEL_URL>/pixel/<tracking-id>.gif
```

`send_email` and `send_draft` responses include the generated `trackingId`.

## Fastmail API Token Setup

1. Log in to Fastmail
2. Go to **Settings → Privacy & Security → API tokens**
3. Create a new token
4. Export it as `FASTMAIL_API_TOKEN`

## Credits

- Original project: [`MadLlama25/fastmail-mcp`](https://github.com/MadLlama25/fastmail-mcp)
- Fork and enhancements: [`mzogithub/fastmail-mcp`](https://github.com/mzogithub/fastmail-mcp)

## License

MIT. See `LICENSE`.
