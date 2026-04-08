// ================================================================
// FIXILY.TN — Backend complet en UN SEUL FICHIER
// Déployer directement sur Render.com
// ================================================================
require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const mysql     = require('mysql2/promise');
const path      = require('path');
const fs        = require('fs');

// ── Pool MySQL ──────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  port:     +process.env.DB_PORT || 3306,
  database: process.env.DB_NAME || 'fixily_db',
  user:     process.env.DB_USER || 'fixily_user',
  password: process.env.DB_PASSWORD || '',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4',
  timezone: '+01:00',
});
pool.getConnection()
  .then(c => { console.log('✅ MySQL OK'); c.release(); })
  .catch(e => { console.error('❌ MySQL:', e.message); process.exit(1); });

// ── Auth middleware ─────────────────────────────────────────────
const authMw = (req,res,next) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({error:'Non authentifié.'});
  try { req.user = jwt.verify(h.slice(7), process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({error:'Token invalide.'}); }
};
const adminOnly   = (r,s,n) => r.user?.type==='admin'   ? n() : s.status(403).json({error:'Admin requis.'});
const artisanOnly = (r,s,n) => r.user?.type==='artisan' ? n() : s.status(403).json({error:'Artisan requis.'});
const clientOnly  = (r,s,n) => r.user?.type==='client'  ? n() : s.status(403).json({error:'Client requis.'});

// ── App Express ──────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy:'cross-origin' } }));
app.use(morgan('combined'));
app.use(express.json({ limit:'10mb' }));
app.use(express.urlencoded({ extended:true }));
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use('/api/', rateLimit({ windowMs:15*60*1000, max:300, message:{error:'Trop de requêtes.'} }));
app.use('/api/auth/login', rateLimit({ windowMs:15*60*1000, max:10, message:{error:'Trop de tentatives.'} }));
const uploadsDir = path.join(__dirname,'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir,{recursive:true});
app.use('/uploads', express.static(uploadsDir));

// ── Helpers ───────────────────────────────────────────────────────
const sign = (u) => jwt.sign({id:u.id,type:u.type,name:u.name,email:u.email}, process.env.JWT_SECRET, {expiresIn:process.env.JWT_EXPIRES_IN||'7d'});
function safeUser(u){const{password_hash,...s}=u;return s;}

// ================================================================
// ROUTES AUTH
// ================================================================
const authRouter = require('express').Router();

authRouter.post('/register', async (req,res) => {
  const {type,name,email,password,confirm_password,phone,city,region,address,bio,category,whatsapp,birth_date} = req.body;
  if(!['client','artisan'].includes(type)) return res.status(400).json({error:'Type invalide.'});
  if(!name?.trim()) return res.status(400).json({error:'Nom requis.'});
  if(!email?.trim()) return res.status(400).json({error:'Email requis.'});
  if(!phone?.trim()) return res.status(400).json({error:'Téléphone requis.'});
  if(!city?.trim()) return res.status(400).json({error:'Ville requise.'});
  if(!password||password.length<6) return res.status(400).json({error:'Mot de passe : 6 caractères minimum.'});
  if(password!==confirm_password) return res.status(400).json({error:'Mots de passe différents.'});
  if(type==='artisan'&&!category) return res.status(400).json({error:'Catégorie requise.'});
  const conn = await pool.getConnection();
  try {
    const [ex] = await conn.query('SELECT id FROM users WHERE email=?',[email.toLowerCase()]);
    if(ex.length) return res.status(409).json({error:'Email déjà utilisé.'});
    const hash = await bcrypt.hash(password,12);
    await conn.beginTransaction();
    const [r] = await conn.query(
      'INSERT INTO users (type,name,email,phone,password_hash,city,region,address,bio,birth_date) VALUES (?,?,?,?,?,?,?,?,?,?)',
      [type,name.trim(),email.toLowerCase(),phone,hash,city,region||null,address||null,bio||null,birth_date||null]
    );
    const userId = r.insertId;
    if(type==='artisan') await conn.query('INSERT INTO artisan_profiles (user_id,category,whatsapp) VALUES (?,?,?)',[userId,category,whatsapp||phone]);
    await conn.commit();
    const [[u]] = await pool.query('SELECT * FROM users WHERE id=?',[userId]);
    res.status(201).json({token:sign(u),user:safeUser(u)});
  } catch(e){ await conn.rollback(); console.error(e); res.status(500).json({error:'Erreur serveur.'}); }
  finally { conn.release(); }
});

authRouter.post('/login', async (req,res) => {
  const {email,password} = req.body;
  if(!email||!password) return res.status(400).json({error:'Email et mot de passe requis.'});
  const [rows] = await pool.query(
    'SELECT u.*,ap.plan,ap.badge_recommended,ap.category,ap.rating,ap.leads_used,ap.is_validated FROM users u LEFT JOIN artisan_profiles ap ON ap.user_id=u.id WHERE u.email=? AND u.is_active=1',
    [email.toLowerCase()]
  );
  if(!rows.length) return res.status(401).json({error:'Identifiants incorrects.'});
  const u = rows[0];
  if(!await bcrypt.compare(password,u.password_hash)) return res.status(401).json({error:'Identifiants incorrects.'});
  res.json({token:sign(u),user:safeUser(u)});
});

authRouter.get('/me', authMw, async (req,res) => {
  const [rows] = await pool.query(
    'SELECT u.*,ap.plan,ap.badge_recommended,ap.category,ap.whatsapp,ap.rating,ap.reviews_count,ap.jobs_count,ap.leads_used,ap.response_rate,ap.is_validated FROM users u LEFT JOIN artisan_profiles ap ON ap.user_id=u.id WHERE u.id=?',
    [req.user.id]
  );
  if(!rows.length) return res.status(404).json({error:'Introuvable.'});
  res.json(safeUser(rows[0]));
});

authRouter.put('/me', authMw, async (req,res) => {
  const {name,phone,city,region,address,bio,birth_date,whatsapp,category,services,tags} = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('UPDATE users SET name=COALESCE(NULLIF(?,\'\'),name),phone=COALESCE(NULLIF(?,\'\'),phone),city=COALESCE(NULLIF(?,\'\'),city),region=COALESCE(?,region),address=COALESCE(?,address),bio=COALESCE(?,bio),birth_date=COALESCE(?,birth_date) WHERE id=?',
      [name||null,phone||null,city||null,region||null,address||null,bio||null,birth_date||null,req.user.id]);
    if(req.user.type==='artisan'){
      if(whatsapp||category) await conn.query('UPDATE artisan_profiles SET whatsapp=COALESCE(?,whatsapp),category=COALESCE(?,category) WHERE user_id=?',[whatsapp||null,category||null,req.user.id]);
      const [[ap]] = await conn.query('SELECT id FROM artisan_profiles WHERE user_id=?',[req.user.id]);
      if(Array.isArray(services)&&ap){
        await conn.query('DELETE FROM artisan_services WHERE artisan_id=?',[ap.id]);
        for(let i=0;i<services.length;i++) await conn.query('INSERT INTO artisan_services (artisan_id,label,sort_order) VALUES (?,?,?)',[ap.id,services[i],i]);
      }
      if(Array.isArray(tags)&&ap){
        await conn.query('DELETE FROM artisan_tags WHERE artisan_id=?',[ap.id]);
        for(const t of tags) await conn.query('INSERT INTO artisan_tags (artisan_id,tag) VALUES (?,?)',[ap.id,t]);
      }
    }
    await conn.commit();
    res.json({message:'Profil mis à jour.'});
  } catch(e){ await conn.rollback(); res.status(500).json({error:'Erreur serveur.'}); }
  finally { conn.release(); }
});

authRouter.put('/password', authMw, async (req,res) => {
  const {current_password,new_password,confirm_password} = req.body;
  if(!current_password||!new_password) return res.status(400).json({error:'Champs requis.'});
  if(new_password.length<6) return res.status(400).json({error:'Trop court.'});
  if(new_password!==confirm_password) return res.status(400).json({error:'Mots de passe différents.'});
  const [[u]] = await pool.query('SELECT password_hash FROM users WHERE id=?',[req.user.id]);
  if(!await bcrypt.compare(current_password,u.password_hash)) return res.status(401).json({error:'Mot de passe actuel incorrect.'});
  const hash = await bcrypt.hash(new_password,12);
  await pool.query('UPDATE users SET password_hash=? WHERE id=?',[hash,req.user.id]);
  res.json({message:'Mot de passe mis à jour.'});
});

app.use('/api/auth', authRouter);

// ================================================================
// ROUTES ARTISANS
// ================================================================
const artisansRouter = require('express').Router();

artisansRouter.get('/', async (req,res) => {
  const {category,city,sort='rating',page=1,limit=20} = req.query;
  const offset=(parseInt(page)-1)*parseInt(limit);
  let where='WHERE ap.is_validated=1 AND u.is_active=1'; const params=[];
  if(category){where+=' AND ap.category=?';params.push(category);}
  if(city){where+=' AND u.city=?';params.push(city);}
  const orderMap={rating:'ap.rating DESC',reviews:'ap.reviews_count DESC',newest:'u.created_at DESC'};
  const order=orderMap[sort]||'ap.rating DESC';
  try {
    const [rows] = await pool.query(`SELECT u.id,u.name,u.city,u.avatar_url,ap.id as artisan_id,ap.category,u.bio,ap.rating,ap.reviews_count,ap.jobs_count,ap.badge_recommended,ap.plan,ap.whatsapp,u.phone,GROUP_CONCAT(DISTINCT ast.tag ORDER BY ast.tag SEPARATOR ',') as tags,GROUP_CONCAT(DISTINCT asv.label ORDER BY asv.sort_order SEPARATOR ',') as services FROM users u JOIN artisan_profiles ap ON ap.user_id=u.id LEFT JOIN artisan_tags ast ON ast.artisan_id=ap.id LEFT JOIN artisan_services asv ON asv.artisan_id=ap.id ${where} GROUP BY u.id,ap.id ORDER BY ${order} LIMIT ? OFFSET ?`,[...params,parseInt(limit),offset]);
    res.json(rows.map(a=>({...a,tags:a.tags?a.tags.split(','):[],services:a.services?a.services.split(','):[]})));
  } catch(e) { console.error('artisans list error:',e.message); res.status(500).json({error:'Erreur serveur.'}); }
});

artisansRouter.get('/:id', async (req,res) => {
  const [[a]] = await pool.query('SELECT u.id,u.name,u.city,u.phone,u.avatar_url,u.bio,ap.id as artisan_id,ap.category,ap.rating,ap.reviews_count,ap.jobs_count,ap.response_rate,ap.badge_recommended,ap.plan,ap.whatsapp,ap.views_count FROM users u JOIN artisan_profiles ap ON ap.user_id=u.id WHERE u.id=? AND ap.is_validated=1 AND u.is_active=1',[req.params.id]);
  if(!a) return res.status(404).json({error:'Artisan introuvable.'});
  await pool.query('UPDATE artisan_profiles SET views_count=views_count+1 WHERE id=?',[a.artisan_id]);
  const [services] = await pool.query('SELECT label FROM artisan_services WHERE artisan_id=? ORDER BY sort_order',[a.artisan_id]);
  const [tags]     = await pool.query('SELECT tag FROM artisan_tags WHERE artisan_id=?',[a.artisan_id]);
  const [works]    = await pool.query('SELECT * FROM portfolio_works WHERE artisan_id=? AND status="approved" ORDER BY created_at DESC LIMIT 20',[a.artisan_id]);
  const [reviews]  = await pool.query('SELECT r.rating,r.comment,r.created_at,u.name as client_name,sr.service FROM reviews r JOIN users u ON u.id=r.client_id JOIN service_requests sr ON sr.id=r.request_id WHERE r.artisan_id=? AND r.is_public=1 ORDER BY r.created_at DESC LIMIT 30',[a.artisan_id]);
  res.json({...a,services:services.map(s=>s.label),tags:tags.map(t=>t.tag),works,reviews});
});

app.use('/api/artisans', artisansRouter);

// ================================================================
// ROUTES REQUESTS (demandes + interventions + validation)
// ================================================================
const requestsRouter = require('express').Router();

async function getArtisanUserId(artisanProfileId){
  const [[ap]]=await pool.query('SELECT user_id FROM artisan_profiles WHERE id=?',[artisanProfileId]);
  return ap?.user_id;
}
async function recalcBadge(conn,artisanId){
  const [[ap]]=await conn.query('SELECT rating,jobs_count,response_rate FROM artisan_profiles WHERE id=?',[artisanId]);
  const badge=ap.rating>=4.5&&ap.jobs_count>=20&&ap.response_rate>=90;
  await conn.query('UPDATE artisan_profiles SET badge_recommended=? WHERE id=?',[badge?1:0,artisanId]);
}

// Client crée une demande
requestsRouter.post('/', authMw, clientOnly, async (req,res) => {
  const {artisan_user_id,service,description,city,address,preferred_date,contact_method}=req.body;
  if(!artisan_user_id||!service) return res.status(400).json({error:'Artisan et service requis.'});
  const [[ap]]=await pool.query('SELECT id,plan,leads_used,leads_reset_at FROM artisan_profiles WHERE user_id=? AND is_validated=1',[artisan_user_id]);
  if(!ap) return res.status(404).json({error:'Artisan introuvable.'});
  if(ap.plan==='free'){
    const now=new Date(),resetAt=ap.leads_reset_at?new Date(ap.leads_reset_at):null;
    const needsReset=!resetAt||now.getMonth()!==resetAt.getMonth()||now.getFullYear()!==resetAt.getFullYear();
    if(needsReset) await pool.query('UPDATE artisan_profiles SET leads_used=0,leads_reset_at=NOW() WHERE id=?',[ap.id]);
    else if(ap.leads_used>=5) return res.status(429).json({error:'Artisan a atteint sa limite de demandes ce mois.'});
  }
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [r]=await conn.query('INSERT INTO service_requests (client_id,artisan_id,service,description,city,address,preferred_date,contact_method) VALUES (?,?,?,?,?,?,?,?)',
      [req.user.id,ap.id,service,description||null,city||null,address||null,preferred_date||null,contact_method||'whatsapp']);
    await conn.query('UPDATE artisan_profiles SET leads_used=leads_used+1,contacts_count=contacts_count+1 WHERE id=?',[ap.id]);
    await conn.commit();
    res.status(201).json({id:r.insertId,message:"Demande envoyée."});
  } catch(e){await conn.rollback();res.status(500).json({error:'Erreur serveur.'});}
  finally{conn.release();}
});

// Client — ses demandes
requestsRouter.get('/my', authMw, clientOnly, async (req,res) => {
  const [rows]=await pool.query('SELECT sr.*,u.name as artisan_name,u.phone as artisan_phone,u.city as artisan_city,u.avatar_url,ap.category,ap.whatsapp as artisan_whatsapp,ap.rating,ip.id as photo_id,ip.before_url,ip.after_url,ip.status as photo_status,ip.note as artisan_note,rv.rating as my_rating,rv.comment as my_comment FROM service_requests sr JOIN artisan_profiles ap ON ap.id=sr.artisan_id JOIN users u ON u.id=ap.user_id LEFT JOIN intervention_photos ip ON ip.request_id=sr.id LEFT JOIN reviews rv ON rv.request_id=sr.id WHERE sr.client_id=? ORDER BY sr.created_at DESC',[req.user.id]);
  res.json(rows);
});

// Artisan — ses demandes reçues
requestsRouter.get('/artisan/received', authMw, artisanOnly, async (req,res) => {
  const [[ap]]=await pool.query('SELECT id FROM artisan_profiles WHERE user_id=?',[req.user.id]);
  if(!ap) return res.status(404).json({error:'Profil introuvable.'});
  const [rows]=await pool.query('SELECT sr.*,uc.name as client_name,uc.phone as client_phone,uc.city as client_city,uc.avatar_url as client_avatar,ip.id as photo_id,ip.status as photo_status,ip.rejection_reason FROM service_requests sr JOIN users uc ON uc.id=sr.client_id LEFT JOIN intervention_photos ip ON ip.request_id=sr.id WHERE sr.artisan_id=? ORDER BY sr.created_at DESC',[ap.id]);
  res.json(rows);
});

// Artisan accepte/refuse
requestsRouter.put('/:id/respond', authMw, artisanOnly, async (req,res) => {
  const {action,message}=req.body;
  if(!['accept','decline'].includes(action)) return res.status(400).json({error:'Action invalide.'});
  const [[sr]]=await pool.query('SELECT * FROM service_requests WHERE id=?',[req.params.id]);
  if(!sr) return res.status(404).json({error:'Demande introuvable.'});
  const uid=await getArtisanUserId(sr.artisan_id);
  if(uid!==req.user.id) return res.status(403).json({error:'Accès refusé.'});
  await pool.query('UPDATE service_requests SET status=?,artisan_response=?,artisan_replied_at=NOW() WHERE id=?',[action==='accept'?'accepted':'cancelled',message||null,req.params.id]);
  res.json({message:action==='accept'?'Demande acceptée.':'Demande refusée.'});
});

// Artisan démarre
requestsRouter.put('/:id/start', authMw, artisanOnly, async (req,res) => {
  const [[sr]]=await pool.query('SELECT * FROM service_requests WHERE id=?',[req.params.id]);
  if(!sr||sr.status!=='accepted') return res.status(400).json({error:'Demande non acceptée.'});
  const uid=await getArtisanUserId(sr.artisan_id);
  if(uid!==req.user.id) return res.status(403).json({error:'Accès refusé.'});
  await pool.query("UPDATE service_requests SET status='in_progress' WHERE id=?",[req.params.id]);
  res.json({message:'Intervention démarrée.'});
});

// Artisan soumet photos
requestsRouter.post('/:id/photos', authMw, artisanOnly, async (req,res) => {
  const {before_url,after_url,note}=req.body;
  if(!before_url||!after_url) return res.status(400).json({error:'Photos avant et après requises.'});
  const [[sr]]=await pool.query('SELECT * FROM service_requests WHERE id=?',[req.params.id]);
  if(!sr) return res.status(404).json({error:'Demande introuvable.'});
  if(!['accepted','in_progress'].includes(sr.status)) return res.status(400).json({error:'Statut invalide.'});
  const uid=await getArtisanUserId(sr.artisan_id);
  if(uid!==req.user.id) return res.status(403).json({error:'Accès refusé.'});
  const [[existing]]=await pool.query('SELECT id FROM intervention_photos WHERE request_id=?',[req.params.id]);
  if(existing) return res.status(409).json({error:'Photos déjà soumises pour cette demande.'});
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('INSERT INTO intervention_photos (request_id,artisan_id,before_url,after_url,note) VALUES (?,?,?,?,?)',[req.params.id,sr.artisan_id,before_url,after_url,note||null]);
    await conn.query("UPDATE service_requests SET status='awaiting_validation' WHERE id=?",[req.params.id]);
    await conn.commit();
    res.status(201).json({message:'Photos soumises. En attente de validation du client.'});
  } catch(e){await conn.rollback();res.status(500).json({error:'Erreur serveur.'});}
  finally{conn.release();}
});

// Client valide — UNIQUEMENT LE CLIENT DE CETTE DEMANDE
requestsRouter.put('/:id/validate', authMw, clientOnly, async (req,res) => {
  const {decision,rejection_reason}=req.body;
  if(!['approve','reject'].includes(decision)) return res.status(400).json({error:'Décision invalide.'});
  const [[sr]]=await pool.query('SELECT * FROM service_requests WHERE id=?',[req.params.id]);
  if(!sr) return res.status(404).json({error:'Demande introuvable.'});
  if(sr.client_id!==req.user.id) return res.status(403).json({error:"Vous n'êtes pas le client de cette demande."});
  if(sr.status!=='awaiting_validation') return res.status(400).json({error:'Pas de photos en attente.'});
  const [[photo]]=await pool.query('SELECT * FROM intervention_photos WHERE request_id=?',[req.params.id]);
  if(!photo) return res.status(404).json({error:'Photos introuvables.'});
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    if(decision==='approve'){
      await conn.query("UPDATE intervention_photos SET status='approved',validated_by=?,validated_at=NOW() WHERE id=?",[req.user.id,photo.id]);
      await conn.query("UPDATE service_requests SET status='completed',completed_at=NOW() WHERE id=?",[req.params.id]);
      await conn.query('UPDATE artisan_profiles SET jobs_count=jobs_count+1 WHERE id=?',[sr.artisan_id]);
      const [[ap]]=await conn.query('SELECT ap.category FROM artisan_profiles ap WHERE ap.id=?',[sr.artisan_id]);
      await conn.query("INSERT INTO portfolio_works (artisan_id,request_id,photo_id,title,description,before_url,after_url,category,status) VALUES (?,?,?,?,?,?,?,?,'approved')",
        [sr.artisan_id,sr.id,photo.id,sr.service,photo.note,photo.before_url,photo.after_url,ap?.category||null]);
    } else {
      if(!rejection_reason?.trim()) return res.status(400).json({error:'Motif de rejet requis.'});
      await conn.query("UPDATE intervention_photos SET status='rejected',validated_by=?,validated_at=NOW(),rejection_reason=? WHERE id=?",[req.user.id,rejection_reason,photo.id]);
      await conn.query("UPDATE service_requests SET status='rejected' WHERE id=?",[req.params.id]);
    }
    await conn.commit();
    res.json({message:decision==='approve'?'Intervention validée !':'Photos rejetées.'});
  } catch(e){await conn.rollback();res.status(500).json({error:'Erreur serveur.'});}
  finally{conn.release();}
});

// Client laisse un avis
requestsRouter.post('/:id/review', authMw, clientOnly, async (req,res) => {
  const {rating,comment}=req.body;
  if(!rating||rating<1||rating>5) return res.status(400).json({error:'Note invalide.'});
  const [[sr]]=await pool.query('SELECT * FROM service_requests WHERE id=?',[req.params.id]);
  if(!sr) return res.status(404).json({error:'Demande introuvable.'});
  if(sr.client_id!==req.user.id) return res.status(403).json({error:'Accès refusé.'});
  if(sr.status!=='completed') return res.status(400).json({error:'Intervention non terminée.'});
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('INSERT INTO reviews (request_id,artisan_id,client_id,rating,comment) VALUES (?,?,?,?,?)',[sr.id,sr.artisan_id,req.user.id,rating,comment||null]);
    const [[stats]]=await conn.query('SELECT AVG(rating) as avg_r,COUNT(*) as cnt FROM reviews WHERE artisan_id=?',[sr.artisan_id]);
    await conn.query('UPDATE artisan_profiles SET rating=?,reviews_count=? WHERE id=?',[parseFloat(stats.avg_r).toFixed(2),stats.cnt,sr.artisan_id]);
    await recalcBadge(conn,sr.artisan_id);
    await conn.commit();
    res.status(201).json({message:'Avis publié !'});
  } catch(e){await conn.rollback();if(e.code==='ER_DUP_ENTRY')return res.status(409).json({error:'Avis déjà posté.'});res.status(500).json({error:'Erreur serveur.'});}
  finally{conn.release();}
});

app.use('/api/requests', requestsRouter);

// ================================================================
// ROUTES ADS (Régie publicitaire)
// ================================================================
const adsRouter = require('express').Router();

adsRouter.get('/active', async (req,res) => {
  const {position}=req.query;
  let posClause="position IN ('both','home','artisans')";
  if(position==='home') posClause="position IN ('both','home')";
  if(position==='artisans') posClause="position IN ('both','artisans')";
  const [rows]=await pool.query(`SELECT * FROM ads WHERE status='active' AND ${posClause} AND starts_at<=NOW() AND (ends_at IS NULL OR ends_at>NOW()) AND impressions_count<impressions_max ORDER BY RAND() LIMIT 1`);
  if(!rows.length) return res.json({empty:true,message:'Votre pub ici'});
  await pool.query('UPDATE ads SET impressions_count=impressions_count+1 WHERE id=?',[rows[0].id]);
  if(rows[0].impressions_count+1>=rows[0].impressions_max) await pool.query("UPDATE ads SET status='expired' WHERE id=?",[rows[0].id]);
  res.json({empty:false,ad:rows[0]});
});

adsRouter.post('/:id/click', async (req,res) => {
  await pool.query('UPDATE ads SET clicks_count=clicks_count+1 WHERE id=?',[req.params.id]).catch(()=>{});
  res.json({ok:true});
});

adsRouter.get('/admin', authMw, adminOnly, async (req,res) => {
  const [rows]=await pool.query('SELECT a.*,u.name as created_by_name,ROUND(a.clicks_count/NULLIF(a.impressions_count,0)*100,2) as ctr FROM ads a LEFT JOIN users u ON u.id=a.created_by ORDER BY a.created_at DESC');
  res.json(rows);
});
adsRouter.get('/admin/stats', authMw, adminOnly, async (req,res) => {
  const [[t]]=await pool.query('SELECT COUNT(*) n FROM ads');
  const [[a]]=await pool.query("SELECT COUNT(*) n FROM ads WHERE status='active'");
  const [[imp]]=await pool.query('SELECT COALESCE(SUM(impressions_count),0) n FROM ads');
  const [[clk]]=await pool.query('SELECT COALESCE(SUM(clicks_count),0) n FROM ads');
  const [[rev]]=await pool.query('SELECT COALESCE(SUM(price_dt),0) n FROM ads');
  res.json({total:t.n,active:a.n,total_impressions:imp.n,total_clicks:clk.n,avg_ctr:imp.n>0?((clk.n/imp.n)*100).toFixed(2):0,total_revenue_dt:parseFloat(rev.n)});
});
adsRouter.post('/admin', authMw, adminOnly, async (req,res) => {
  const {title,advertiser,image_url,target_url,alt_text,position,size,impressions_max,status,starts_at,ends_at,price_dt,notes}=req.body;
  if(!title||!advertiser||!target_url) return res.status(400).json({error:'Titre, annonceur et URL requis.'});
  const [r]=await pool.query('INSERT INTO ads (title,advertiser,image_url,target_url,alt_text,position,size,impressions_max,status,starts_at,ends_at,price_dt,notes,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    [title,advertiser,image_url||'',target_url,alt_text||'',position||'both',size||'banner',impressions_max||10000,status||'draft',starts_at||new Date(),ends_at||null,price_dt||0,notes||null,req.user.id]);
  res.status(201).json({id:r.insertId,message:'Campagne créée.'});
});
adsRouter.put('/admin/:id', authMw, adminOnly, async (req,res) => {
  const {title,advertiser,image_url,target_url,alt_text,position,size,impressions_max,status,starts_at,ends_at,price_dt,notes}=req.body;
  await pool.query('UPDATE ads SET title=COALESCE(?,title),advertiser=COALESCE(?,advertiser),image_url=COALESCE(?,image_url),target_url=COALESCE(?,target_url),alt_text=COALESCE(?,alt_text),position=COALESCE(?,position),size=COALESCE(?,size),impressions_max=COALESCE(?,impressions_max),status=COALESCE(?,status),starts_at=COALESCE(?,starts_at),ends_at=?,price_dt=COALESCE(?,price_dt),notes=COALESCE(?,notes) WHERE id=?',
    [title||null,advertiser||null,image_url||null,target_url||null,alt_text||null,position||null,size||null,impressions_max||null,status||null,starts_at||null,ends_at||null,price_dt||null,notes||null,req.params.id]);
  res.json({message:'Mise à jour.'});
});
adsRouter.put('/admin/:id/status', authMw, adminOnly, async (req,res) => {
  const {status}=req.body;
  await pool.query('UPDATE ads SET status=? WHERE id=?',[status,req.params.id]);
  res.json({message:`Statut → ${status}`});
});
adsRouter.put('/admin/:id/reset', authMw, adminOnly, async (req,res) => {
  await pool.query("UPDATE ads SET impressions_count=0,clicks_count=0,status='active' WHERE id=?",[req.params.id]);
  res.json({message:'Remis à zéro.'});
});
adsRouter.delete('/admin/:id', authMw, adminOnly, async (req,res) => {
  await pool.query('DELETE FROM ads WHERE id=?',[req.params.id]);
  res.json({message:'Supprimé.'});
});

app.use('/api/ads', adsRouter);

// ================================================================
// ROUTES ADMIN
// ================================================================
const adminRouter = require('express').Router();
adminRouter.use(authMw, adminOnly);

adminRouter.get('/dashboard', async (req,res) => {
  const [[c]]=await pool.query("SELECT COUNT(*) n FROM users WHERE type='client' AND is_active=1");
  const [[a]]=await pool.query('SELECT COUNT(*) n FROM artisan_profiles');
  const [[pr]]=await pool.query("SELECT COUNT(*) n FROM artisan_profiles WHERE plan='premium'");
  const [[mrr]]=await pool.query("SELECT COALESCE(SUM(amount_dt),0) n FROM subscriptions WHERE status='active' AND YEAR(started_at)=YEAR(NOW()) AND MONTH(started_at)=MONTH(NOW())");
  const [[rp]]=await pool.query("SELECT COUNT(*) n FROM reports WHERE status='pending'");
  const [[sr]]=await pool.query("SELECT COUNT(*) n FROM service_requests WHERE status='pending'");
  const [[pw]]=await pool.query("SELECT COUNT(*) n FROM portfolio_works WHERE status='pending'");
  const [[msg]]=await pool.query('SELECT COUNT(*) n FROM contact_messages WHERE is_read=0');
  res.json({clients:c.n,artisans:a.n,premium:pr.n,mrr:+mrr.n,reports:rp.n,pending_requests:sr.n,pending_works:pw.n,unread_messages:msg.n});
});

adminRouter.get('/artisans', async (req,res) => {
  const [rows]=await pool.query('SELECT u.id,u.name,u.email,u.phone,u.city,u.is_active,u.created_at,ap.id ap_id,ap.category,ap.plan,ap.rating,ap.badge_recommended,ap.is_validated,ap.leads_used,ap.reviews_count,ap.jobs_count FROM users u JOIN artisan_profiles ap ON ap.user_id=u.id ORDER BY u.created_at DESC');
  res.json(rows);
});
adminRouter.put('/artisans/:id/validate', async (req,res) => {
  await pool.query('UPDATE artisan_profiles SET is_validated=1 WHERE user_id=?',[req.params.id]);
  res.json({message:'Validé.'});
});
adminRouter.put('/artisans/:id/suspend', async (req,res) => {
  await pool.query('UPDATE users SET is_active=0 WHERE id=?',[req.params.id]);
  res.json({message:'Suspendu.'});
});
adminRouter.put('/artisans/:id/plan', async (req,res) => {
  const {plan,expires_at}=req.body;
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('UPDATE artisan_profiles SET plan=?,plan_expires_at=? WHERE user_id=?',[plan,expires_at||null,req.params.id]);
    if(plan==='premium'){
      const [[ap]]=await conn.query('SELECT id FROM artisan_profiles WHERE user_id=?',[req.params.id]);
      const exp=expires_at?new Date(expires_at):new Date(Date.now()+30*86400000);
      await conn.query("INSERT INTO subscriptions (artisan_id,plan,amount_dt,expires_at,status,created_by) VALUES (?,'premium',19.00,?,'active',?)",[ap.id,exp,req.user.id]);
    }
    await conn.commit();
    res.json({message:`Plan → ${plan}`});
  } catch(e){await conn.rollback();res.status(500).json({error:'Erreur.'});}
  finally{conn.release();}
});
adminRouter.get('/clients', async (req,res) => {
  const [rows]=await pool.query('SELECT u.id,u.name,u.email,u.phone,u.city,u.region,u.is_active,u.created_at,(SELECT COUNT(*) FROM service_requests sr WHERE sr.client_id=u.id) requests_count,(SELECT COUNT(*) FROM reviews rv WHERE rv.client_id=u.id) reviews_count FROM users u WHERE u.type=\'client\' ORDER BY u.created_at DESC');
  res.json(rows);
});
adminRouter.get('/requests', async (req,res) => {
  const {status}=req.query; let where=''; const p=[];
  if(status){where='WHERE sr.status=?';p.push(status);}
  const [rows]=await pool.query(`SELECT sr.*,uc.name client_name,ua.name artisan_name,ap.category FROM service_requests sr JOIN users uc ON uc.id=sr.client_id JOIN artisan_profiles ap ON ap.id=sr.artisan_id JOIN users ua ON ua.id=ap.user_id ${where} ORDER BY sr.created_at DESC LIMIT 100`,p);
  res.json(rows);
});
adminRouter.get('/works/pending', async (req,res) => {
  const [rows]=await pool.query('SELECT pw.*,u.name artisan_name,u.city FROM portfolio_works pw JOIN artisan_profiles ap ON ap.id=pw.artisan_id JOIN users u ON u.id=ap.user_id WHERE pw.status=\'pending\' ORDER BY pw.created_at ASC');
  res.json(rows);
});
adminRouter.put('/works/:id', async (req,res) => {
  const {status}=req.body;
  if(!['approved','rejected'].includes(status)) return res.status(400).json({error:'Invalide.'});
  await pool.query('UPDATE portfolio_works SET status=?,moderated_by=?,moderated_at=NOW() WHERE id=?',[status,req.user.id,req.params.id]);
  res.json({message:`${status==='approved'?'Approuvé':'Rejeté'}.`});
});
adminRouter.get('/reports', async (req,res) => {
  const [rows]=await pool.query('SELECT r.*,uf.name from_name,ua.name against_name FROM reports r JOIN users uf ON uf.id=r.from_user_id JOIN users ua ON ua.id=r.against_user_id ORDER BY r.created_at DESC');
  res.json(rows);
});
adminRouter.put('/reports/:id', async (req,res) => {
  const {status,action_taken}=req.body;
  await pool.query('UPDATE reports SET status=?,action_taken=?,resolved_by=?,resolved_at=NOW() WHERE id=?',[status,action_taken||null,req.user.id,req.params.id]);
  res.json({message:'Mis à jour.'});
});
adminRouter.get('/config', async (req,res) => {
  const [rows]=await pool.query('SELECT config_key,config_value FROM site_config');
  const c={}; rows.forEach(r=>c[r.config_key]=r.config_value); res.json(c);
});
adminRouter.put('/config', async (req,res) => {
  const conn=await pool.getConnection();
  try {
    await conn.beginTransaction();
    for(const [k,v] of Object.entries(req.body))
      await conn.query('INSERT INTO site_config (config_key,config_value,updated_by) VALUES (?,?,?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),updated_by=VALUES(updated_by)',[k,v,req.user.id]);
    await conn.commit();
    res.json({message:'Sauvegardé.'});
  } catch(e){await conn.rollback();res.status(500).json({error:'Erreur.'});}
  finally{conn.release();}
});
adminRouter.get('/messages', async (req,res) => {
  const [rows]=await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
  res.json(rows);
});
adminRouter.put('/messages/:id/read', async (req,res) => {
  await pool.query('UPDATE contact_messages SET is_read=1 WHERE id=?',[req.params.id]);
  res.json({message:'Lu.'});
});
adminRouter.get('/subscriptions', async (req,res) => {
  const [rows]=await pool.query('SELECT s.*,u.name artisan_name,u.email FROM subscriptions s JOIN artisan_profiles ap ON ap.id=s.artisan_id JOIN users u ON u.id=ap.user_id ORDER BY s.created_at DESC');
  res.json(rows);
});
adminRouter.post('/recalc-badges', async (req,res) => {
  await pool.query('UPDATE artisan_profiles SET badge_recommended=(rating>=4.5 AND jobs_count>=20 AND response_rate>=90)');
  res.json({message:'Badges recalculés.'});
});

app.use('/api/admin', adminRouter);

// ================================================================
// ROUTES SIMPLES
// ================================================================
app.post('/api/contact', async (req,res) => {
  const {name,email,phone,message}=req.body;
  if(!name||!message) return res.status(400).json({error:'Nom et message requis.'});
  await pool.query('INSERT INTO contact_messages (name,email,phone,message) VALUES (?,?,?,?)',[name,email||null,phone||null,message]);
  res.status(201).json({message:'Message envoyé.'});
});

app.get('/api/config', async (req,res) => {
  const [rows]=await pool.query('SELECT config_key,config_value FROM site_config');
  const c={}; rows.forEach(r=>c[r.config_key]=r.config_value); res.json(c);
});

app.get('/health', (req,res) => res.json({status:'ok',ts:new Date().toISOString()}));

// ================================================================
// DÉMARRAGE
// ================================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Fixily.tn API — port ${PORT}`);
  console.log(`   DB: ${process.env.DB_NAME}@${process.env.DB_HOST}`);
});

// Handler global — évite le crash sur erreur non catchée
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err.message);
  // Ne pas crasher le processus
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Rejection:', reason?.message || reason);
  // Ne pas crasher le processus
});
