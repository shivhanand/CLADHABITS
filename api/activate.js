import crypto from 'node:crypto';

const COOKIE_NAME='clad_session';
const SESSION_DAYS=365;
const ACTIVATION_URL='https://glmsrbyczxikwlhxyalv.supabase.co/functions/v1/cladhabits-license-activate';

function b64url(input){
  return Buffer.from(input).toString('base64url');
}

function hashUserAgent(userAgent){
  return crypto.createHash('sha256').update(userAgent||'').digest('base64url');
}

function signSession(payload,secret){
  const body=b64url(JSON.stringify(payload));
  const sig=crypto.createHmac('sha256',secret).update(body).digest('base64url');
  return body+'.'+sig;
}

function normalize(value){
  return String(value||'').trim();
}

function json(status,body,extraHeaders={}){
  return new Response(JSON.stringify(body),{
    status,
    headers:{'content-type':'application/json; charset=utf-8',...extraHeaders}
  });
}

export default async function handler(request){
  if(request.method!=='POST')return json(405,{valid:false,message:'Method not allowed.'});

  const sessionSecret=process.env.CLAD_SESSION_SECRET;
  if(!sessionSecret)return json(500,{valid:false,message:'Access security is not configured.'});

  try{
    const body=await request.json();
    const licenseKey=normalize(body?.licenseKey).toUpperCase();
    const email=normalize(body?.email).toLowerCase();
    const fingerprint=normalize(body?.fingerprint);

    if(!licenseKey||!fingerprint){
      return json(400,{valid:false,message:'Enter your license key and activate from this device.'});
    }

    const upstream=await fetch(ACTIVATION_URL,{
      method:'POST',
      headers:{'content-type':'application/json'},
      body:JSON.stringify({
        license_key:licenseKey,
        email,
        fingerprint
      })
    });

    const data=await upstream.json().catch(()=>({}));
    if(!upstream.ok||!data?.ok){
      const status=upstream.status||403;
      const reason=data?.reason||'activation_failed';
      const message =
        reason==='email_mismatch' ? 'The email does not match your purchase.' :
        reason==='activation_limit_reached' ? 'This license is already active on another device.' :
        reason==='invalid_or_expired' ? 'License not found, inactive, or expired.' :
        'Activation failed. Please check your details and try again.';
      return json(status,{valid:false,reason,message});
    }

    const now=Math.floor(Date.now()/1000);
    const rawExpiry=data.expires_at ? Math.floor(new Date(data.expires_at).getTime()/1000) : now+SESSION_DAYS*86400;
    const exp=Math.max(now+60,rawExpiry);

    const session=signSession({
      v:1,
      licenseId:data.license_id||null,
      exp,
      ua:hashUserAgent(request.headers.get('user-agent')||'')
    },sessionSecret);

    const headers=new Headers({'content-type':'application/json; charset=utf-8'});
    headers.append(
      'Set-Cookie',
      COOKIE_NAME+'='+session+'; Path=/; Max-Age='+Math.max(60,exp-now)+'; HttpOnly; Secure; SameSite=Lax'
    );

    return new Response(JSON.stringify({
      valid:true,
      message:'CLADHABITS activated on this device.'
    }),{status:200,headers});
  }catch(error){
    console.error('CLADHABITS activation error:',error);
    return json(500,{valid:false,message:'Activation service temporarily unavailable.'});
  }
}
