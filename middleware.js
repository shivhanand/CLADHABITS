const COOKIE_NAME = 'clad_session';

function base64urlToBytes(value){
  const padded=value.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((value.length+3)%4);
  const raw=atob(padded);
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}

function base64urlEncodeBytes(bytes){
  let raw='';
  for(const b of bytes) raw+=String.fromCharCode(b);
  return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function verifyToken(token,secret,userAgent){
  if(!token||!secret)return false;
  const parts=token.split('.');
  if(parts.length!==2)return false;
  const [payloadB64,sigB64]=parts;
  try{
    const payload=JSON.parse(new TextDecoder().decode(base64urlToBytes(payloadB64)));
    if(!payload||typeof payload.exp!=='number'||payload.exp<Math.floor(Date.now()/1000))return false;
    if(!payload.ua)return false;

    const uaBytes=new TextEncoder().encode(userAgent||'');
    const uaHashBuffer=await crypto.subtle.digest('SHA-256',uaBytes);
    const uaHash=base64urlEncodeBytes(new Uint8Array(uaHashBuffer));
    if(uaHash!==payload.ua)return false;

    const key=await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      {name:'HMAC',hash:'SHA-256'},
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      'HMAC',
      key,
      base64urlToBytes(sigB64),
      new TextEncoder().encode(payloadB64)
    );
  }catch{
    return false;
  }
}

export default async function middleware(request){
  const url=new URL(request.url);
  const pathname=url.pathname;

  if(pathname!=='/'&&pathname!=='/index.html') return;

  const secret=process.env.CLAD_SESSION_SECRET;
  const token=request.cookies.get(COOKIE_NAME)?.value;
  const ok=await verifyToken(token,secret,request.headers.get('user-agent')||'');

  if(ok)return;

  return Response.redirect(new URL('/activate.html',request.url),302);
}

export const config={matcher:['/','/index.html']};
