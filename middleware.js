const crypto = require("crypto");

function fromB64url(s){
  s = s.replace(/-/g,"+").replace(/_/g,"/");
  while(s.length % 4) s += "=";
  return Buffer.from(s,"base64");
}
function verify(token){
  if(!token || !process.env.LICENSE_SECRET) return false;
  const parts = token.split(".");
  if(parts.length !== 2) return false;
  const body = parts[0];
  const sig = fromB64url(parts[1]);
  const expected = crypto.createHmac("sha256",process.env.LICENSE_SECRET).update(body).digest();
  if(sig.length !== expected.length || !crypto.timingSafeEqual(sig,expected)) return false;
  try{
    const data = JSON.parse(fromB64url(body).toString("utf8"));
    return data.v === 1 && Number(data.exp) > Math.floor(Date.now()/1000);
  }catch{return false}
}

export default function middleware(request){
  const {pathname, searchParams} = new URL(request.url);
  if(pathname !== "/app.html") return;
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)clad_license=([^;]+)/);
  const token = match ? match[1] : searchParams.get("license");
  if(verify(token)){
    if(!match && token){
      const headers = new Headers(request.headers);
      headers.set("cookie", cookie + (cookie ? "; " : "") + "clad_license=" + token);
      return new Response(null,{status:307,headers:{Location:"/app.html", "Set-Cookie":"clad_license="+token+"; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax"}});
    }
    return;
  }
  return Response.redirect(new URL("/index.html",request.url),302);
}

export const config = { matcher: ["/app.html"] };
