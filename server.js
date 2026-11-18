'use strict';
/**
 * Fire Zone — servidor multiplayer WebSocket (salas 1v1: host + guest)
 *
 * Protocolo (o mesmo que o cliente do index.html já usa, nada foi alterado):
 *
 *  Cliente -> Servidor
 *    {t:'join', c:codigoDaSala, r:'host'|'guest'}   entra/cria sala
 *    {t:'p',    d:{...}}                            atualiza a presença (delta, mesclado)
 *
 *  Servidor -> Cliente
 *    {t:'ok'}                    entrou na sala
 *    {t:'err', m:'mensagem'}     erro
 *    {t:'s', o:{id:presenca}}    lista COMPLETA dos OUTROS jogadores da sala (nunca você mesmo)
 *    {t:'p', i:id, d:{...}}      o jogador `id` atualizou a presença (delta)
 *    {t:'l', i:id}               o jogador `id` saiu
 *
 * Regras: no máximo 2 jogadores por sala (1 host + 1 guest). Sem banco de dados,
 * sem Supabase, sem chaves/senhas. Tudo em memória.
 *
 * Variáveis de ambiente (todas opcionais):
 *   PORT             porta (o Render define sozinho)
 *   MAX_CLIENTS      limite de conexões simultâneas   (padrão 300)
 *   ALLOWED_ORIGINS  origens permitidas, separadas por vírgula (padrão: qualquer uma)
 *                    ex.: ALLOWED_ORIGINS=https://meujogo.com,https://outro.com
 */

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

// ---------------------------------------------------------------- config
const PORT = Number(process.env.PORT) || 3000;
const MAX_CLIENTS = Number(process.env.MAX_CLIENTS) || 300;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map((s) => s.trim()).filter(Boolean);

const MAX_PAYLOAD = 16 * 1024;        // bytes por mensagem
const MAX_PRESENCE_KEYS = 64;         // chaves por atualização de presença
const JOIN_TIMEOUT_MS = 10000;        // tempo p/ mandar o "join" depois de conectar
const HEARTBEAT_MS = 25000;           // ping (mantém a conexão viva no Render e derruba mortas)
const RATE_CAPACITY = 120;            // rajada máxima de mensagens
const RATE_REFILL_PER_SEC = 60;       // mensagens/s sustentadas
const RATE_MAX_STRIKES = 200;         // mensagens descartadas até derrubar quem faz flood
const CODE_RE = /^[A-Z0-9]{4,12}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ---------------------------------------------------------------- estado
/** @type {Map<string, {code:string, host:Player|null, guest:Player|null}>} */
const rooms = new Map();

/**
 * @typedef {{id:string, ws:WebSocket, role:'host'|'guest'|null, room:object|null,
 *            presence:object, tokens:number, ts:number, strikes:number, joinTimer:NodeJS.Timeout|null}} Player
 */

// ---------------------------------------------------------------- utilidades
function send(ws, obj) {
  if (ws.readyState !== WebSocket.OPEN) return;
  try { ws.send(JSON.stringify(obj)); } catch (_) { /* conexão caindo */ }
}

function newId() { return crypto.randomBytes(4).toString('hex'); }

function originAllowed(origin) {
  if (ALLOWED_ORIGINS.includes('*')) return true;
  return !!origin && ALLOWED_ORIGINS.includes(origin);
}

/** Aceita só objeto simples; remove chaves perigosas. Retorna null se inválido. */
function cleanPresence(d) {
  if (d === null || typeof d !== 'object' || Array.isArray(d)) return null;
  const keys = Object.keys(d);
  if (keys.length > MAX_PRESENCE_KEYS) return null;
  const out = {};
  for (const k of keys) {
    if (FORBIDDEN_KEYS.has(k)) continue;
    out[k] = d[k];
  }
  return out;
}

function members(room) {
  return [room.host, room.guest].filter(Boolean);
}

/** Objeto {id: presença} com os OUTROS jogadores da sala (o cliente troca o mapa inteiro ao receber 's'). */
function othersOf(room, me) {
  const o = {};
  for (const p of members(room)) if (p !== me) o[p.id] = p.presence;
  return o;
}

/** Manda a cada participante a lista atualizada dos outros. */
function syncRoom(room) {
  for (const p of members(room)) send(p.ws, { t: 's', o: othersOf(room, p) });
}

// ---------------------------------------------------------------- ações
function joinRoom(p, msg) {
  if (p.room) return send(p.ws, { t: 'err', m: 'Você já está em uma sala' });

  const code = String(msg.c == null ? '' : msg.c).trim().slice(0, 32).toUpperCase();
  if (!CODE_RE.test(code)) return fail(p, 'Código de sala inválido');
  const role = msg.r;
  if (role !== 'host' && role !== 'guest') return fail(p, 'Função inválida');

  let room = rooms.get(code);

  if (role === 'host') {
    if (room && room.host) return fail(p, 'Código já em uso, crie outra sala');
    if (!room) {
      room = { code, host: null, guest: null };
      rooms.set(code, room);
    }
    room.host = p;
  } else {
    if (!room) return fail(p, 'Sala não encontrada');
    if (room.guest || members(room).length >= 2) return fail(p, 'Sala cheia');
    room.guest = p;
  }

  p.room = room;
  p.role = role;
  clearTimeout(p.joinTimer);
  p.joinTimer = null;

  send(p.ws, { t: 'ok' });
  syncRoom(room); // os dois participantes recebem a lista atualizada
}

/** Erro durante o join: avisa e fecha (o cliente também fecha ao receber 'err'). */
function fail(p, m) {
  send(p.ws, { t: 'err', m });
  try { p.ws.close(1000, 'join recusado'); } catch (_) { /* ignore */ }
}

function updatePresence(p, msg) {
  if (!p.room) return send(p.ws, { t: 'err', m: 'Entre em uma sala primeiro' });
  const d = cleanPresence(msg.d);
  if (!d) return send(p.ws, { t: 'err', m: 'Presença inválida' });

  // o papel vem do servidor: ninguém consegue se passar por host/guest pela presença
  if ('role' in d) d.role = p.role;

  Object.assign(p.presence, d); // mesma mesclagem que o cliente faz
  for (const other of members(p.room)) {
    if (other !== p) send(other.ws, { t: 'p', i: p.id, d });
  }
}

function leave(p) {
  clearTimeout(p.joinTimer);
  p.joinTimer = null;
  const room = p.room;
  if (!room) return;
  p.room = null;

  if (room.host === p) room.host = null;
  if (room.guest === p) room.guest = null;

  const rest = members(room);
  if (rest.length === 0) {
    if (rooms.get(room.code) === room) rooms.delete(room.code);
    return;
  }
  for (const other of rest) send(other.ws, { t: 'l', i: p.id });
}

/** Balde de fichas: protege contra flood sem atrapalhar o jogo (~20 msg/s no pior caso). */
function allow(p) {
  const now = Date.now();
  p.tokens = Math.min(RATE_CAPACITY, p.tokens + ((now - p.ts) / 1000) * RATE_REFILL_PER_SEC);
  p.ts = now;
  if (p.tokens >= 1) { p.tokens -= 1; return true; }
  p.strikes += 1;
  if (p.strikes > RATE_MAX_STRIKES) { try { p.ws.close(1008, 'flood'); } catch (_) { /* ignore */ } }
  return false;
}

// ---------------------------------------------------------------- servidor HTTP + WS
const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/health' || url === '/healthz') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    });
    return res.end(JSON.stringify({ ok: true, rooms: rooms.size, clients: wss.clients.size }));
  }
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end('Fire Zone multiplayer server');
});
// o proxy do Render mantém conexões abertas; evita 502 esporádico
server.keepAliveTimeout = 120000;
server.headersTimeout = 121000;

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD, perMessageDeflate: false });

server.on('upgrade', (req, socket, head) => {
  if (!originAllowed(req.headers.origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

wss.on('connection', (ws) => {
  ws.on('error', () => { /* evita derrubar o processo; o 'close' faz a limpeza */ });

  if (wss.clients.size > MAX_CLIENTS) {
    send(ws, { t: 'err', m: 'Servidor cheio, tente de novo em instantes' });
    return ws.close(1013, 'cheio');
  }

  /** @type {Player} */
  const p = {
    id: newId(), ws, role: null, room: null, presence: {},
    tokens: RATE_CAPACITY, ts: Date.now(), strikes: 0, joinTimer: null,
  };
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  p.joinTimer = setTimeout(() => {
    if (!p.room) { send(ws, { t: 'err', m: 'Tempo esgotado para entrar na sala' }); try { ws.close(1008, 'sem join'); } catch (_) { /* ignore */ } }
  }, JOIN_TIMEOUT_MS);

  ws.on('message', (data, isBinary) => {
    ws.isAlive = true;
    if (isBinary) return;
    if (!allow(p)) return;
    try {
      let msg;
      try { msg = JSON.parse(data.toString()); } catch (_) { return send(ws, { t: 'err', m: 'Mensagem inválida' }); }
      if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) return send(ws, { t: 'err', m: 'Mensagem inválida' });

      if (msg.t === 'join') joinRoom(p, msg);
      else if (msg.t === 'p') updatePresence(p, msg);
      // outros tipos são ignorados
    } catch (e) {
      send(ws, { t: 'err', m: 'Erro interno' });
    }
  });

  ws.on('close', () => leave(p));
});

// derruba conexões "fantasma" (celular que perdeu o sinal sem fechar)
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch (_) { /* ignore */ }
  }
}, HEARTBEAT_MS);
heartbeat.unref();

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Fire Zone server ouvindo na porta ${PORT}`);
});

// ---------------------------------------------------------------- encerramento limpo (deploy do Render envia SIGTERM)
function shutdown() {
  console.log('Encerrando…');
  clearInterval(heartbeat);
  for (const ws of wss.clients) { try { ws.close(1001, 'servidor reiniciando'); } catch (_) { /* ignore */ } }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
