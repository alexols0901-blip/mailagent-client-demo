# MailAgent AI — client demo

A self-contained presentation demo. Serve index.html as a static site with no build command and publish directory `.`.

The owner page lists company websites and supports creating and branding companies. Each company has a distinct URL, for example `/?company=alpine-studio`, with only Inbox and Settings navigation. The company inbox combines fictional Gmail and Infomaniak messages with provider and status filters.

Use Simulate new email to demonstrate automatic processing: exact sender forwarding rules are matched case insensitively; a matching sender is forwarded to the specified human without an AI reply. Otherwise the demo generates a canned automatic reply if the agent is active. Paused agents and disconnected providers do not reply. Rules affect future incoming messages only. Replies and forwarding are simulations, not real sending.

Company data, settings, messages and logos are stored in this browser using localStorage. Separate page navigation is a presentation feature, not authentication or server-side tenant isolation. A new company's share link includes its name and color so the page can be reconstructed in another browser; other settings, logos and messages are not synced. Never use real customer or mailbox information.

No real authentication, tenant isolation, passkeys, AI processing, inbox access, background monitoring or email sending is implemented. Company IDs do not register separate domains. Files contain only fictional sample data.

For Render: choose Static Site, no build command, publish directory `.`. The static demo needs no paid compute or database.
