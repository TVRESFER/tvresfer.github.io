import { randomBytes, createHash, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';

// No credentials in source. Configure both values as Netlify environment variables.
const PUBLIC_ORIGIN = 'https://tvresfer.github.io';
const OWNER_ID = 351447491;
const REPOSITORY_ID = 1443052356;
const REPOSITORY = 'TVRESFER/tvresfer.github.io';
const FLOW_COOKIE = '__Host-resfer_oauth';
const baseHeaders = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};
function seal(data, secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', createHash('sha256').update(secret).digest(), iv);
  const content = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), content]).toString('base64url');
}
function unseal(value, secret) {
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < 29 || bytes.length > 4096) throw Error('cookie');
  const decipher = createDecipheriv('aes-256-gcm', createHash('sha256').update(secret).digest(), bytes.subarray(0,12));
  decipher.setAuthTag(bytes.subarray(12,28));
  return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString());
}
function cookie(value, age = 600) {
  return `${FLOW_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;
}
function same(a,b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x=Buffer.from(a), y=Buffer.from(b);
  return x.length===y.length && timingSafeEqual(x,y);
}
function result(data, status = 200) {
  const nonce = randomBytes(16).toString('base64');
  const payload = JSON.stringify({type:'resfer-github-auth', ...data}).replace(/</g,'\\u003c');
  const html = `<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acceso RESFER</title><style nonce="${nonce}">body{font:18px system-ui;max-width:520px;margin:15vh auto;padding:24px;line-height:1.6}a{color:#215fe5}</style><h1>Acceso a RESFER</h1><p id="message">Comprobando acceso…</p><a href="${PUBLIC_ORIGIN}/#administrar">Volver al panel</a><script nonce="${nonce}">history.replaceState(null,'',location.pathname);const data=${payload};document.getElementById('message').textContent=data.error||'Acceso confirmado. Puedes volver a la ventana del panel.';if(window.opener){window.opener.postMessage(data,${JSON.stringify(PUBLIC_ORIGIN)});if(!data.error)window.close();}</script></html>`;
  return new Response(html,{status,headers:{...baseHeaders,'Content-Type':'text/html; charset=utf-8','Set-Cookie':cookie('',0),'Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`}});
}
export function createHandler({env=process.env, fetchImpl=fetch, now=Date.now} = {}) {
  return async function(request) {
    const url = new URL(request.url);
    if (request.method !== 'GET') return new Response('Método no permitido.',{status:405,headers:baseHeaders});
    const clientId=env.GITHUB_CLIENT_ID, secret=env.GITHUB_CLIENT_SECRET;
    const configuredOrigin=env.AUTH_ORIGIN || env.URL;
    if (!clientId || !secret || !configuredOrigin) return result({error:'El acceso todavía no está configurado.'},503);
    let origin;
    try {origin=new URL(configuredOrigin).origin;}catch{return result({error:'Configuración del acceso incorrecta.'},503);}
    if (!origin.startsWith('https://') || url.origin!==origin) return result({error:'Dirección de acceso no válida.'},400);
    const callback=origin+'/auth/callback';
    if (url.pathname==='/auth/start') {
      const nonce=url.searchParams.get('nonce') || '';
      if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) return result({error:'Abre el acceso desde el panel de RESFER.'},400);
      const state=randomBytes(32).toString('base64url');
      const verifier=randomBytes(32).toString('base64url');
      const authorize=new URL('https://github.com/login/oauth/authorize');
      authorize.search=new URLSearchParams({client_id:clientId, redirect_uri:callback, state,
        code_challenge:createHash('sha256').update(verifier).digest('base64url'), code_challenge_method:'S256',
        login:'TVRESFER', allow_signup:'false', scope:'offline_access'}).toString();
      return new Response(null,{status:302,headers:{...baseHeaders,Location:authorize.href,
        'Set-Cookie':cookie(seal({state,verifier,nonce,expires:now()+600000},secret))}});
    }
    if(url.pathname!=='/auth/callback') return new Response('No encontrado.',{status:404,headers:baseHeaders});
    let flow;
    try {
      const raw=(request.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(FLOW_COOKIE+'='))?.slice(FLOW_COOKIE.length+1);
      flow=unseal(raw||'',secret);
      if (!Number.isFinite(flow.expires) || flow.expires<now() || flow.expires>now()+600000 ||
          !same(flow.state,url.searchParams.get('state'))) throw Error('state');
    } catch {return result({error:'El acceso ha caducado. Cierra esta ventana y pulsa Entrar con GitHub otra vez.'},400);}
    if(url.searchParams.has('error')) return result({nonce:flow.nonce,error:'No se ha autorizado el acceso. Puedes volver a intentarlo.'},400);
    const code=url.searchParams.get('code');
    if(!code || code.length>512) return result({nonce:flow.nonce,error:'No se recibió la autorización de GitHub.'},400);
    try {
      const tokenResponse=await fetchImpl('https://github.com/login/oauth/access_token',{
        method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),
        headers:{Accept:'application/json','Content-Type':'application/x-www-form-urlencoded','User-Agent':'RESFER-Admin'},
        body:new URLSearchParams({client_id:clientId,client_secret:secret,code,redirect_uri:callback,code_verifier:flow.verifier,repository_id:String(REPOSITORY_ID)}).toString(),
      });
      if(!tokenResponse.ok) throw Error('exchange');
      const token=await tokenResponse.json();
      if(typeof token.access_token!=='string' || !/^ghu_[A-Za-z0-9_]+$/.test(token.access_token) ||
          !Number.isFinite(token.expires_in) || token.expires_in<=0 || token.expires_in>28800) throw Error('token');
      const headers={Authorization:'Bearer '+token.access_token,Accept:'application/vnd.github+json',
        'X-GitHub-Api-Version':'2026-03-10','User-Agent':'RESFER-Admin'};
      const userResponse=await fetchImpl('https://api.github.com/user',{headers,redirect:'error',signal:AbortSignal.timeout(15000)});
      if(!userResponse.ok) throw Error('user');
      const user=await userResponse.json();
      if(user.id!==OWNER_ID) return result({nonce:flow.nonce,error:'Este panel solo permite entrar con la cuenta TVRESFER.'},403);
      const repoResponse=await fetchImpl('https://api.github.com/repos/'+REPOSITORY,{headers,redirect:'error',signal:AbortSignal.timeout(15000)});
      if(!repoResponse.ok) throw Error('repository');
      const repo=await repoResponse.json();
      if(repo.id!==REPOSITORY_ID || repo.permissions?.push!==true) return result({nonce:flow.nonce,error:'Instala la aplicación de RESFER en tvresfer.github.io con permiso para gestionar su contenido.'},403);
      // Never send the refresh token or client secret to the browser.
      return result({nonce:flow.nonce,accessToken:token.access_token,expiresIn:token.expires_in,login:'TVRESFER'});
    } catch {
      return result({nonce:flow.nonce,error:'No se pudo completar el acceso con GitHub. Vuelve al panel e inténtalo de nuevo.'},502);
    }
  };
}
export default createHandler();
export const config={path:['/auth/start','/auth/callback']};
