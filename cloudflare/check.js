import { connect } from 'cloudflare:sockets';

async function probe(port, secureTransport) {
  let socket, timer;
  try {
    socket = connect({ hostname: 'mail.infomaniak.com', port }, { secureTransport });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Connection timed out')), 8000); })
    ]);
    return { port, connected: true, transport: secureTransport === 'on' ? 'TLS' : 'TCP (STARTTLS not tested)' };
  } catch (error) {
    return { port, connected: false, error: String(error.message).slice(0, 180) };
  } finally {
    clearTimeout(timer);
    if (socket) await socket.close().catch(() => {});
  }
}

export default {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path !== '/check') return new Response('MailAgent network test only. Open /check to test fixed Infomaniak ports. No credentials, inbox access or email sending.', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    const results = [];
    // Sequential to stay below Workers simultaneous connection limits.
    for (const [port, transport] of [[993, 'on'], [465, 'on'], [587, 'off']]) results.push(await probe(port, transport));
    let gmail;
    try {
      const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', { signal: AbortSignal.timeout(8000) });
      gmail = { reachable: response.status === 401, status: response.status, note: '401 is expected because this test sends no credentials.' };
    } catch (error) { gmail = { reachable: false, error: String(error.message).slice(0, 180) }; }
    return Response.json({ purpose: 'Network connectivity only. No email account was accessed and no message was sent.', results, gmail }, { headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
  }
};
