const crypto=require('crypto');
function b64urlDecode(s){return Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'),'base64');}
function b64urlEncode(b){return Buffer.from(b).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function verify(token,secret,userAgent){
 if(!token||!secret)return false;
 const p=token.split('.');
 if(p.length!==2)return false;
 try{
  const payload=JSON.parse(b64urlDecode(p[0]).toString('utf8'));
  if(!payload||typeof payload.exp!=='number'||payload.exp<Math.floor(Date.now()/1000)||!payload.ua)return false;
  if(b64urlEncode(crypto.createHash('sha256').update(userAgent||'').digest())!==payload.ua)return false;
  const expected=crypto.createHmac('sha256',secret).update(p[0]).digest(), actual=b64urlDecode(p[1]);
  return expected.length===actual.length&&crypto.timingSafeEqual(expected,actual);
 }catch{return false;}
}
module.exports=async function(req,res){
 res.setHeader('Cache-Control','no-store');
 const cookie=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('clad_session='));
 const token=cookie?decodeURIComponent(cookie.slice(13)):'';
 const ok=verify(token,process.env.CLAD_SESSION_SECRET,req.headers['user-agent']||'');
 res.statusCode=ok?200:401;
 res.setHeader('Content-Type','application/json');
 res.end(JSON.stringify({ok}));
};