// ════════════════════════════════════════════════════════════════════
// BACKEND DASHBOARD — Approvazione utente (link cliccato dall'admin via email)
// Endpoint: GET /api/approva?email=...&token=...
// Imposta approvato=true e invia email di conferma all'utente.
// ════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

function tokenApprovazione(email){
  const SECRET = process.env.DASH_APPROVE_SECRET || 'cambia-approve-secret';
  return crypto.createHmac('sha256', SECRET).update(email).digest('hex').substring(0, 40);
}

function pagina(titolo, messaggio, colore){
  return `<!DOCTYPE html><html lang="it"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${titolo}</title>
    <style>
      body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0c050e;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
      .box{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:40px;max-width:420px;text-align:center}
      h1{color:${colore};margin:0 0 16px;font-size:24px}
      p{color:#c0c0d0;line-height:1.6}
    </style></head><body>
    <div class="box"><h1>${titolo}</h1><p>${messaggio}</p></div>
    </body></html>`;
}

module.exports = async (req, res) => {
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET = process.env.SUPABASE_SECRET;

  const email = String((req.query && req.query.email) || '').trim().toLowerCase();
  const token = String((req.query && req.query.token) || '');

  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  if(!SUPABASE_URL || !SUPABASE_SECRET){
    res.status(500).send(pagina('Errore', 'Configurazione server incompleta.', '#ff4444'));
    return;
  }

  // Verifica token
  if(!email || token !== tokenApprovazione(email)){
    res.status(403).send(pagina('Link non valido', 'Questo link di approvazione non è valido o è scaduto.', '#ff4444'));
    return;
  }

  try {
    // Imposta approvato = true
    const upd = await fetch(`${SUPABASE_URL}/rest/v1/utenti_dashboard?email=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: {
        'apikey': SUPABASE_SECRET,
        'Authorization': `Bearer ${SUPABASE_SECRET}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
      },
      body: JSON.stringify({ approvato: true }),
    });
    const aggiornati = await upd.json();
    if(!Array.isArray(aggiornati) || aggiornati.length === 0){
      res.status(404).send(pagina('Utente non trovato', 'Non è stato trovato nessun account con questa email.', '#ff4444'));
      return;
    }
    const utente = aggiornati[0];

    // Invia email di conferma all'utente
    const RESEND_API_KEY = process.env.RESEND_API_KEY;
    const EMAIL_FROM = process.env.EMAIL_FROM || 'onboarding@resend.dev';
    const BASE_URL = process.env.DASH_BASE_URL || '';
    if(RESEND_API_KEY){
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: `Dashboard Minimal Gamers <${EMAIL_FROM}>`,
            to: [email],
            subject: 'Il tuo accesso è stato approvato! 🎉',
            html: `
              <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
                <h2 style="color:#8b00ff">Accesso approvato!</h2>
                <p>Ciao ${utente.nome || ''}, il tuo accesso alla dashboard lead di Minimal Gamers è stato approvato.</p>
                <p>Ora puoi accedere con la tua email e la password che hai scelto:</p>
                <p style="text-align:center;margin:30px 0">
                  <a href="${BASE_URL}" style="background:linear-gradient(135deg,#ff0099,#8b00ff);color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold">Accedi alla dashboard</a>
                </p>
              </div>`,
          }),
        });
      } catch(eMail){
        console.error('Errore email conferma:', eMail.message);
      }
    }

    res.status(200).send(pagina('Utente approvato! ✓', `${utente.nome || email} ora può accedere alla dashboard. Gli è stata inviata una email di conferma.`, '#2dd4bf'));

  } catch(e){
    res.status(500).send(pagina('Errore', String(e.message || e), '#ff4444'));
  }
};
