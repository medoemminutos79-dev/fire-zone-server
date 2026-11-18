// Edge Function: owner-sign
// Assina comandos do painel ADM SÓ para contas que estão em public.x1_owners.
// A chave privada nunca sai do servidor (fica em public.x1_admin_keys, acessível só pela service role).
// Deploy com "Verify JWT" DESLIGADO (a própria função valida o token do usuário).
import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const ALG = { name: "ECDSA", namedCurve: "P-256" } as const;
const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const admin = createClient(url, service, { auth: { persistSession: false } });

  // 1) quem está chamando? (token do login do jogador)
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return json({ error: "no_token" }, 401);
  const { data: u, error: ue } = await admin.auth.getUser(token);
  if (ue || !u?.user) return json({ error: "bad_token" }, 401);

  // 2) é Owner no servidor?
  const { data: own, error: oe } = await admin.from("x1_owners").select("uid").eq("uid", u.user.id).maybeSingle();
  if (oe) return json({ error: "owner_check_failed" }, 500);
  if (!own) return json({ error: "not_owner" }, 403);

  // 3) valida o comando
  let body: { d?: unknown };
  try { body = await req.json(); } catch { return json({ error: "bad_json" }, 400); }
  const d = body?.d;
  if (typeof d !== "string" || d.length < 2 || d.length > 20000) return json({ error: "bad_payload" }, 400);
  try {
    const m = JSON.parse(d);
    if (typeof m?.t !== "string" || typeof m?.c !== "string" || typeof m?.id !== "string") throw 0;
  } catch { return json({ error: "bad_command" }, 400); }

  // 4) carrega (ou cria na 1ª vez) a chave de assinatura
  let { data: row } = await admin.from("x1_admin_keys").select("private_jwk").eq("id", 1).maybeSingle();
  if (!row) {
    const kp = await crypto.subtle.generateKey(ALG, true, ["sign", "verify"]);
    const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
    await admin.from("x1_admin_keys").upsert(
      { id: 1, private_jwk: priv, public_jwk: { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y } },
      { onConflict: "id", ignoreDuplicates: true },
    );
    ({ data: row } = await admin.from("x1_admin_keys").select("private_jwk").eq("id", 1).maybeSingle());
    if (!row) return json({ error: "key_failed" }, 500);
  }

  // 5) assina (formato IEEE-P1363 = o que o navegador espera no verify)
  const key = await crypto.subtle.importKey("jwk", row.private_jwk, ALG, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(d));
  return json({ sg: b64(sig) });
});
