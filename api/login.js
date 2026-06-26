// ════════════════════════════════════════════════════════════════════
// BACKEND DASHBOARD — Login (verifica email + password)
// Endpoint: POST /api/login  body: { email, password }
// Restituisce un token di sessione firmato se le credenziali sono valide
// E se l'utente è stato APPROVATO.
// ════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// Hash della password (stesso metodo usato in registrazione)
function hashPassword(password, salt){
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// Genera un token di sessione firmato, valido 7 giorni
function generaToken(email){
  const SALT = process.env.DASH_SESSION_SALT || 'cambia-questa-frase';
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 giorni
  const firma = crypto.createHmac('sha256', SALT).update(email + '|' + exp).digest('hex').substring(0, 32);
  return `${email}|${exp}|${firma}`;
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
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');

    if(!email || !password){
      res.status(400).json({ error: 'Inserisci email e password' });
      return;
    }

    // Cerca l'utente su Supabase
    const r = await fetch(`${SUPABASE_URL}/rest/v1/utenti_dashboard?email=eq.${encodeURIComponent(email)}&select=*`, {
      headers: {
        'apikey': SUPABASE_SECRET,
        'Authorization': `Bearer ${SUPABASE_SECRET}`,
      },
    });
    const utenti = await r.json();

    if(!Array.isArray(utenti) || utenti.length === 0){
      res.status(401).json({ error: 'Email o password non corretti' });
      return;
    }

    const u = utenti[0];

    // Verifica approvazione
    if(!u.approvato){
      res.status(403).json({ error: 'Il tuo account è in attesa di approvazione dall\'amministratore.' });
      return;
    }

    // Verifica password
    const hashTentativo = hashPassword(password, u.salt);
    if(hashTentativo !== u.password_hash){
      res.status(401).json({ error: 'Email o password non corretti' });
      return;
    }

    // OK! Genera token di sessione
    const token = generaToken(email);
    res.status(200).json({ success: true, token: token, nome: u.nome || email });

  } catch(e){
    res.status(500).json({ error: 'Errore server', dettaglio: String(e.message || e) });
  }
};
