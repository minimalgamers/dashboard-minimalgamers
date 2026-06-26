// ════════════════════════════════════════════════════════════════════
// BACKEND DASHBOARD — Registrazione nuovo utente
// Endpoint: POST /api/registra  body: { nome, email, password }
// Crea l'utente come "non approvato" e invia email all'admin per approvare.
//
// VARIABILI D'AMBIENTE su Vercel:
//   SUPABASE_URL, SUPABASE_SECRET
//   RESEND_API_KEY    = re_xxx
//   ADMIN_EMAIL       = info@minimalgamers.it  (dove arrivano le richieste)
//   EMAIL_FROM        = noreply@minimalgamers.it (quando il dominio è verificato)
//   DASH_BASE_URL     = https://dashboard-minimalgamers.vercel.app (URL della dashboard)
//   DASH_APPROVE_SECRET = una frase segreta per il link di approvazione
// ════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

function hashPassword(password, salt){
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// Crea un token di approvazione firmato per il link nell'email all'admin
function tokenApprovazione(email){
  const SECRET = process.env.DASH_APPROVE_SECRET || 'cambia-approve-secret';
  return crypto.createHmac('sha256', SECRET).update(email).digest('hex').substring(0, 40);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if(req.method === 'OPTIONS'){ res.status(200).end(); return; }
  if(req.method !== 'POST'){ res.status(405).json({ error: 'Method not allowed' }); return; }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET = process.env.SUPABASE_SECRET;
  if(!SUPABASE_URL || !SUPABASE_SECRET){
    res.status(500).json({ error: 'Configurazione server incompleta' });
    return;
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const nome = String(body.nome || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');

    if(!nome || !email || !password){
      res.status(400).json({ error: 'Compila tutti i campi' });
      return;
    }
    if(password.length < 6){
      res.status(400).json({ error: 'La password deve avere almeno 6 caratteri' });
      return;
    }
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){
      res.status(400).json({ error: 'Email non valida' });
      return;
    }

    // Controlla se l'email esiste già
    const check = await fetch(`${SUPABASE_URL}/rest/v1/utenti_dashboard?email=eq.${encodeURIComponent(email)}&select=email`, {
      headers: { 'apikey': SUPABASE_SECRET, 'Authorization': `Bearer ${SUPABASE_SECRET}` },
    });
    const esistenti = await check.json();
    if(Array.isArray(esistenti) && esistenti.length > 0){
      res.status(409).json({ error: 'Esiste già un account con questa email' });
      return;
    }

    // Crea hash password
    const salt = crypto.randomBytes(16).toString('hex');
    const password_hash = hashPassword(password, salt);

    // Salva utente come NON approvato
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/utenti_dashboard`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_SECRET,
        'Authorization': `Bearer ${SUPABASE_SECRET}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify({
        nome: nome,
        email: email,
        password_hash: password_hash,
        salt: salt,
        approvato: false,
      }),
    });
    if(!ins.ok){
      const txt = await ins.text();
      res.status(500).json({ error: 'Errore creazione account', dettaglio: txt });
      return;
    }

    // Invia email all'admin per approvare (se Resend è configurato)
    const RESEND_API_KEY = process.env.RESEND_API_KEY;
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
    const EMAIL_FROM = process.env.EMAIL_FROM || 'onboarding@resend.dev';
    const BASE_URL = process.env.DASH_BASE_URL || '';

    if(RESEND_API_KEY && ADMIN_EMAIL){
      const tok = tokenApprovazione(email);
      const linkApprova = `${BASE_URL}/api/approva?email=${encodeURIComponent(email)}&token=${tok}`;
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${RESEND_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: `Dashboard Minimal Gamers <${EMAIL_FROM}>`,
            to: [ADMIN_EMAIL],
            subject: `Nuova richiesta di accesso: ${nome}`,
            html: `
              <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
                <h2 style="color:#8b00ff">Nuova richiesta di accesso alla dashboard</h2>
                <p><strong>${nome}</strong> (${email}) ha richiesto l'accesso alla dashboard lead.</p>
                <p>Per approvare questo utente, clicca il pulsante qui sotto:</p>
                <p style="text-align:center;margin:30px 0">
                  <a href="${linkApprova}" style="background:linear-gradient(135deg,#ff0099,#8b00ff);color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold">Approva ${nome}</a>
                </p>
                <p style="color:#888;font-size:13px">Se non riconosci questa richiesta, ignora questa email: l'utente non potrà accedere senza la tua approvazione.</p>
              </div>`,
          }),
        });
      } catch(eMail){
        console.error('Errore invio email approvazione:', eMail.message);
        // Non blocchiamo: l'utente è creato, l'admin può approvare anche manualmente
      }
    }

    res.status(200).json({
      success: true,
      message: 'Registrazione completata! Il tuo account sarà attivo dopo l\'approvazione dell\'amministratore. Riceverai conferma via email.',
    });

  } catch(e){
    res.status(500).json({ error: 'Errore server', dettaglio: String(e.message || e) });
  }
};
