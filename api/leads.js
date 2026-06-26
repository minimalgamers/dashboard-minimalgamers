// ════════════════════════════════════════════════════════════════════
// BACKEND DASHBOARD — Legge i lead da Supabase (chiave nascosta lato server)
// Endpoint: GET /api/leads  (richiede header x-dash-token valido)
//
// VARIABILI D'AMBIENTE su Vercel:
//   SUPABASE_URL      = https://qyjvgyqkhjgryefmcdht.supabase.co
//   SUPABASE_SECRET   = sb_secret_xxx
//   DASH_SESSION_SALT = una frase segreta a piacere (per validare i token di sessione)
// ════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// Verifica che il token di sessione sia valido (firmato dal nostro server al login)
function verificaToken(token){
  const SALT = process.env.DASH_SESSION_SALT || 'cambia-questa-frase';
  if(!token || typeof token !== 'string' || !token.includes('|')) return false;
  const [email, exp, firma] = token.split('|');
  if(!email || !exp || !firma) return false;
  // Token scaduto?
  if(Date.now() > parseInt(exp, 10)) return false;
  // Firma corretta?
  const atteso = crypto.createHmac('sha256', SALT).update(email + '|' + exp).digest('hex').substring(0, 32);
  return firma === atteso;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-dash-token');

  if(req.method === 'OPTIONS'){ res.status(200).end(); return; }
  if(req.method !== 'GET'){ res.status(405).json({ error: 'Method not allowed' }); return; }

  // Controllo autenticazione
  const token = req.headers['x-dash-token'];
  if(!verificaToken(token)){
    res.status(401).json({ error: 'Non autorizzato. Effettua di nuovo il login.' });
    return;
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SECRET = process.env.SUPABASE_SECRET;
  if(!SUPABASE_URL || !SUPABASE_SECRET){
    res.status(500).json({ error: 'Configurazione server incompleta' });
    return;
  }

  try {
    // Legge tutti i lead, più recenti prima
    const r = await fetch(`${SUPABASE_URL}/rest/v1/lead_configuratore?select=*&order=creato_il.desc`, {
      headers: {
        'apikey': SUPABASE_SECRET,
        'Authorization': `Bearer ${SUPABASE_SECRET}`,
      },
    });
    if(!r.ok){
      const txt = await r.text();
      res.status(500).json({ error: 'Errore lettura dati', dettaglio: txt });
      return;
    }
    const leads = await r.json();
    res.status(200).json({ success: true, leads: leads });
  } catch(e){
    res.status(500).json({ error: 'Errore server', dettaglio: String(e.message || e) });
  }
};
