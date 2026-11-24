import express, { Express, NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import puppeteer, { Browser, executablePath, HTTPResponse, Page } from "puppeteer";
import { parse } from "node-html-parser";
import path from "path";
import os from "node:os";
import fs from "node:fs";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

dotenv.config();

const app: Express = express();
app.set("trust proxy", 1);
// Cabeceras de seguridad estándar (X-Content-Type-Options, X-Frame-Options, quita
// X-Powered-By, etc). Es una API JSON pura, así que ninguna de estas cabeceras
// afecta el body ni el status de las respuestas existentes.
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

const port               = process.env.PORT || 3000;
const PAGE_TIMEOUT_MS    = 120_000;
const REQUEST_TIMEOUT_MS = 180_000;

// ─── Manejadores de errores de proceso ───────────────────────────────────────

process.on("unhandledRejection", (reason) => {
  console.error("[process] Unhandled rejection:", reason);
});

process.on("uncaughtException", (err: NodeJS.ErrnoException) => {
  console.error("[process] Uncaught exception:", err.message);
  if (err.code === "EADDRINUSE") {
    console.error("[process] Puerto en uso. Cierra el proceso anterior e intenta de nuevo.");
    process.exit(1);
  }
  // Para otros errores (ej. fallas de Puppeteer en callbacks async), solo loguear
  console.error(err.stack);
});

// ─── Autenticación ───────────────────────────────────────────────────────────

// Comparación constant-time: evita filtrar por timing cuántos caracteres iniciales
// de la key coinciden. Buffer.from(a).length !== Buffer.from(b).length ya corta
// antes de llamar a timingSafeEqual (que exige igual longitud), sin comparar contenido.
function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

// Contador de intentos fallidos de API key por IP. Solo se toca en el branch de
// rechazo: un cliente con la key correcta nunca pasa por acá, así que esto no
// afecta a ningún consumidor legítimo — solo frena el escaneo/fuerza bruta de la key.
const AUTH_FAIL_WINDOW_MS = 60_000;
const AUTH_FAIL_MAX = 20;
const authFailuresByIp = new Map<string, { count: number; windowStart: number }>();

function registerAuthFailure(ip: string): boolean {
  const now = Date.now();
  const entry = authFailuresByIp.get(ip);
  if (!entry || now - entry.windowStart > AUTH_FAIL_WINDOW_MS) {
    authFailuresByIp.set(ip, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= AUTH_FAIL_MAX;
}

function requireApiKey(req: Request, res: Response, next: NextFunction): void {
  const apiKey = process.env.API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: "API_KEY no configurada en el servidor" });
    return;
  }
  const provided = req.headers["x-api-key"];
  if (typeof provided !== "string" || !safeCompare(provided, apiKey)) {
    if (!registerAuthFailure(req.ip ?? "unknown")) {
      res.status(429).json({ error: "Demasiados intentos con API key inválida. Intente más tarde." });
      return;
    }
    res.status(401).json({ error: "API key inválida o ausente" });
    return;
  }
  next();
}

// ─── Rate limiting ───────────────────────────────────────────────────────────

const heavyLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Demasiadas solicitudes. Espere un momento antes de intentarlo de nuevo." },
});

// El SII aplica throttling anti-bot cuando detecta logins muy seguidos con el mismo RUT:
// el redirect post-login se cuelga ~120s en vez de fallar limpio. Forzamos un cooldown
// por RUT para nunca disparar esa protección.
const RUT_COOLDOWN_MS = 30_000;
const lastQueryByRut = new Map<string, number>();

function checkRutCooldown(rut: string, res: Response): boolean {
  // Un lote en curso mantiene una sesión SII abierta con este RUT: abrir otra a la vez
  // haría que el SII bloquee la clave por sesiones concurrentes.
  if (lotesActivosPorRut.has(rut)) {
    res.status(409).json({
      error: "Hay un lote en curso para este RUT. Espere a que termine antes de iniciar otra consulta.",
    });
    return false;
  }
  const last = lastQueryByRut.get(rut);
  const now = Date.now();
  if (last !== undefined && now - last < RUT_COOLDOWN_MS) {
    const waitSec = Math.ceil((RUT_COOLDOWN_MS - (now - last)) / 1000);
    res.status(429).json({
      error: `Debe esperar ${waitSec}s antes de consultar nuevamente este RUT. El SII bloquea logins muy seguidos.`,
    });
    return false;
  }
  lastQueryByRut.set(rut, now);
  return true;
}

// Ambos Map (cooldown por RUT y fallos de auth por IP) solo crecen; sin esta
// limpieza periódica acumulan entradas para siempre en un proceso de larga duración.
setInterval(() => {
  const now = Date.now();
  for (const [rut, ts] of lastQueryByRut) {
    if (now - ts > RUT_COOLDOWN_MS) lastQueryByRut.delete(rut);
  }
  for (const [ip, entry] of authFailuresByIp) {
    if (now - entry.windowStart > AUTH_FAIL_WINDOW_MS) authFailuresByIp.delete(ip);
  }
}, 5 * 60_000).unref();

// ─── Control de concurrencia ─────────────────────────────────────────────────

// Cada request pesado abre un Chromium completo. Sin este límite, N requests
// simultáneos lanzan N navegadores sin techo, arriesgando OOM en la VPS (compartida
// con otros proyectos). El request que excede el cupo simplemente espera en cola;
// si la espera + el resto del trabajo supera REQUEST_TIMEOUT_MS, falla con el mismo
// error de timeout que ya existía (withTimeout), sin cambiar el contrato de la API.
const MAX_CONCURRENT_SESSIONS = Number(process.env.MAX_CONCURRENT_SESSIONS) || 2;

class Semaphore {
  private available: number;
  private queue: (() => void)[] = [];

  constructor(count: number) {
    this.available = count;
  }

  async acquire(): Promise<void> {
    if (this.available > 0) {
      this.available--;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
  }

  release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.available++;
    }
  }
}

const sessionSemaphore = new Semaphore(MAX_CONCURRENT_SESSIONS);

// ─── Helpers de browser ──────────────────────────────────────────────────────

function sessionDir(sessionId: string): string {
  return path.join(os.tmpdir(), `chromeSession_${sessionId}`);
}

function launchBrowser(sessionId: string): Promise<Browser> {
  return puppeteer.launch({
    headless: true,
    executablePath: executablePath(),
    args: [
      "--disable-setuid-sandbox",
      "--no-sandbox",
      "--disable-gpu",
      "--no-first-run",
      "--disable-dev-shm-usage",
    ],
    userDataDir: sessionDir(sessionId),
  });
}

function cleanupSession(sessionId: string): void {
  try {
    fs.rmSync(sessionDir(sessionId), { recursive: true, force: true });
  } catch { /* no-op */ }
}

function formatRut(rut: string): string {
  const [num, dv] = rut.split("-");
  return `${num.replace(/\B(?=(\d{3})+(?!\d))/g, ".")}-${dv}`;
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.goto(
    "https://zeusr.sii.cl//AUT2000/InicioAutenticacion/IngresoRutClave.html?https://misiir.sii.cl/cgi_misii/siihome.cgi",
    { timeout: PAGE_TIMEOUT_MS }
  );
  await page.locator("#rutcntr").fill(formatRut(user));
  await page.locator("#clave").fill(pass);
  await Promise.all([
    page.waitForNavigation({ timeout: PAGE_TIMEOUT_MS }),
    page.click("#bt_ingresar"),
  ]);
  if (page.url().includes("zeusr.sii.cl")) {
    throw new Error("Credenciales SII inválidas o servicio no disponible");
  }
}

// El SII mantiene la sesión activa en su servidor aunque cerremos el browser.
// Sin este logout explícito, tras un par de consultas con el mismo RUT el SII
// bloquea la clave por "múltiples sesiones concurrentes". Best-effort: nunca
// debe tumbar la respuesta ya construida, por eso todos los timeouts son cortos
// y los errores se tragan.
async function logout(page: Page): Promise<void> {
  try {
    await page.goto("https://misiir.sii.cl/cgi_misii/siihome.cgi", {
      waitUntil: "domcontentloaded",
      timeout: 15_000,
    });
    const clicked = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll("a"));
      const exit = links.find((a) => /cerrar\s*sesi|salir del sitio/i.test(a.textContent?.trim() ?? ""));
      if (exit) { (exit as HTMLAnchorElement).click(); return true; }
      return false;
    });
    if (clicked) {
      await page.waitForNavigation({ timeout: 15_000 }).catch(() => {});
    }
    console.log(`[logout] sesión SII cerrada: ${clicked ? "ok" : "enlace no encontrado"}`);
  } catch (e) {
    console.warn("[logout] No se pudo cerrar sesión SII:", (e as Error).message);
  }
}

// Garantiza que el cliente HTTP siempre recibe respuesta, incluso si Puppeteer
// se cuelga internamente. La promesa original sigue corriendo en segundo plano
// (su propio finally igual cierra el browser); solo dejamos de esperarla aquí.
async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Tiempo máximo excedido en: ${label}`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

const BROWSER_CLOSE_TIMEOUT_MS = 10_000;

// El SII a veces deja navegaciones Angular pendientes que cuelgan browser.close()
// indefinidamente (nunca resuelve ni rechaza). Sin este timeout, esa espera colgada
// retiene el proceso Chromium y su sesión en disco para siempre, filtrando recursos
// bajo carga sostenida. Esto corre en el finally, después de responder al cliente:
// no cambia la respuesta HTTP en ningún caso.
async function closeBrowserSafely(browser: Browser, label: string): Promise<void> {
  try {
    await withTimeout(browser.close(), BROWSER_CLOSE_TIMEOUT_MS, label);
  } catch (e) {
    console.warn(`[${label}] browser.close() no respondió, forzando kill:`, (e as Error).message);
    try { browser.process()?.kill("SIGKILL"); } catch { /* intentional */ }
  }
}

// Ejecuta fn con una página de Chromium ya autenticada en el SII. Toma un cupo del
// semáforo, y SIEMPRE lo libera (incluso si Chromium no arranca o el login falla):
// lanzar el navegador dentro del try evita que un fallo de arranque filtre el cupo.
async function conSesionSii<T>(
  label: string,
  rut: string,
  pass: string,
  fn: (page: Page) => Promise<T>
): Promise<T> {
  await sessionSemaphore.acquire();
  const sessionId = randomUUID();
  let browser: Browser | null = null;
  let page: Page | null = null;
  try {
    browser = await launchBrowser(sessionId);
    page = await browser.newPage();
    await login(page, rut, pass);
    return await fn(page);
  } finally {
    if (page) await logout(page);
    if (browser) await closeBrowserSafely(browser, `cierre navegador ${label}`);
    cleanupSession(sessionId);
    sessionSemaphore.release();
  }
}

// ─── Lógica RCV ──────────────────────────────────────────────────────────────


function parseRcvDetails(data: string[], operacion: "COMPRA" | "VENTA"): object[] {
  const details: Record<string, unknown>[] = [];

  for (let k = 0; k < data.length; k++) {
    if (k === 0) continue;
    if (typeof data[k] !== "string") continue;
    for (const line of data[k].split("\n")) {
      if (!line.trim()) continue;
      const v = line.split(";");

      if (operacion === "COMPRA") {
        if (v[0] === "") {
          // Fila de continuación: impuestos adicionales del documento anterior
          const last = details[details.length - 1];
          if (last) {
            (last.otrosImpuestos as object[]).push({
              codigoOtroImpuesto: v[24],
              valorOtroImpuesto:  v[25],
              tasaOtroImpuesto:   v[26],
            });
          }
        } else {
          details.push({
            tipoDTE:                   v[1],
            tipoCompra:                v[2],
            rutProveedor:              v[3],
            razonSocial:               v[4],
            folio:                     v[5],
            fechaEmision:              v[6],
            fechaRecepcion:            v[7],
            montoExento:               v[9],
            montoNeto:                 v[10],
            montoIvaRecuperable:       v[11],
            montoIvaNoRecuperable:     v[12],
            codigoIvaNoRecuperable:    v[13],
            montoTotal:                v[14],
            montoNetoActivoFijo:       v[15],
            ivaActivoFijo:             v[16],
            ivaUsoComun:               v[17],
            impuestoSinDerechoCredito: v[18],
            ivaNoRetenido:             v[19],
            tabacosPuros:              v[20],
            tabacosCigarrillos:        v[21],
            tabacosElaborados:         v[22],
            otrosImpuestos: [{ codigoOtroImpuesto: v[24], valorOtroImpuesto: v[25], tasaOtroImpuesto: v[26] }],
          });
        }
      } else {
        details.push({
          tipoDTE:              v[1],
          tipoCompra:           v[2],
          rutCliente:           v[3],
          razonSocial:          v[4],
          folio:                v[5],
          fechaEmision:         v[6],
          fechaRecepcion:       v[7],
          montoExento:          v[10],
          montoNeto:            v[11],
          montoIvaRecuperable:  v[12],
          montoTotal:           v[13],
          ivaNoRetenido:        v[16],
          valorOtroImpuesto:    v[v.length - 2],
          tasaOtroImpuesto:     v[v.length - 1],
        });
      }
    }
  }
  return details;
}


function parseRcvSummaryFromJson(raw: Record<string, unknown>, operacion: "COMPRA" | "VENTA"): object[] {
  const items = raw.data as Record<string, unknown>[];
  if (!Array.isArray(items)) return [];
  return items.map((item) => {
    const nombre = `${item.dcvNombreTipoDoc}(${item.rsmnTipoDocInteger})`;
    if (operacion === "COMPRA") {
      return {
        tipoDteString:    nombre,
        totalDocumentos:  String(item.rsmnTotDoc),
        montoExento:      String(item.rsmnMntExe ?? 0),
        montoNeto:        String(item.rsmnMntNeto ?? 0),
        ivaRecuperable:   String(item.rsmnMntIVA ?? 0),
        ivaUsoComun:      String(item.rsmnIVAUsoComun ?? 0),
        ivaNoRecuperable: String(item.rsmnMntIVANoRec ?? 0),
        montoTotal:       String(item.rsmnMntTotal ?? 0),
      };
    }
    return {
      tipoDteString:   nombre,
      totalDocumentos: String(item.rsmnTotDoc),
      montoExento:     String(item.rsmnMntExe ?? 0),
      montoNeto:       String(item.rsmnMntNeto ?? 0),
      montoIva:        String(item.rsmnMntIVA ?? 0),
      montoTotal:      String(item.rsmnMntTotal ?? 0),
    };
  });
}

function parseRcvDetailsFromJson(raw: Record<string, unknown>, operacion: "COMPRA" | "VENTA"): object[] {
  // getDetalleCompraExport / getDetalleVentaExport devuelven { data: string[] } en CSV
  const data = raw.data as string[];
  if (!Array.isArray(data)) return [];
  return parseRcvDetails(data, operacion);
}

async function pollUntil(check: () => boolean, timeoutMs: number, label: string): Promise<void> {
  const start = Date.now();
  while (!check() && Date.now() - start < timeoutMs) {
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!check()) throw new Error(`Timeout esperando ${label}`);
}

async function fetchRCV(
  month: string,
  year: string,
  user: string,
  pass: string,
  mode: "compras" | "ventas",
  detallado = false
): Promise<object> {
  return conSesionSii("RCV", user, pass, (page) =>
    descargarRCV(page, month, year, user, mode, detallado)
  );
}

// Descarga el RCV con una página ya autenticada (la usa tanto el endpoint suelto como
// el lote). El listener de respuestas se retira al terminar para que varias descargas
// seguidas en la misma página no acumulen listeners ni respuestas de otra consulta.
async function descargarRCV(
  page: Page,
  month: string,
  year: string,
  user: string,
  mode: "compras" | "ventas",
  detallado = false
): Promise<object> {
  const operacion   = mode === "compras" ? "COMPRA" : "VENTA";
  const ptributario = year + month.padStart(2, "0");
  const rutNum      = user.split("-")[0];
  const dv          = user.split("-")[1];

  let onResponse: ((r: HTTPResponse) => Promise<void>) | null = null;

  try {
    // Todos los acumuladores se llenan via page.on("response") antes de cualquier navegación
    // para evitar race conditions donde la respuesta llega antes de registrar waitForResponse.
    const resumenResponses: Record<string, unknown>[] = [];
    let empresasAutorizadasReceived = false;
    let detalleRaw: Record<string, unknown> | null = null;
    let detalleStatus = 0;

    onResponse = async (r: HTTPResponse) => {
      const url = r.url();
      if (url.includes("sii.cl") && url.includes("services")) {
        console.log(`[net] ${r.status()} ${r.request().method()} ${url}`);
      }
      if (url.includes("getDcvEmpresasAutorizadas")) {
        empresasAutorizadasReceived = true;
      }
      if (url.includes("getResumen") && r.request().method() === "POST" && r.status() === 200) {
        try {
          const data = await r.json() as Record<string, unknown>;
          resumenResponses.push(data);
          const items = data.data as unknown[] | undefined;
          console.log(`[net] getResumen acumulado #${resumenResponses.length}, items: ${Array.isArray(items) ? items.length : "n/a"}`);
        } catch (e) {
          console.warn("[net] getResumen no-JSON:", (e as Error).message);
        }
      }
      if (url.includes("getDetalle")) {
        detalleStatus = r.status();
        if (r.status() === 200) {
          try {
            const data = await r.json() as Record<string, unknown>;
            detalleRaw = data;
            // Solo llaves y cantidad de filas: el contenido trae RUT y razones sociales de terceros.
            const filas = Array.isArray(data.data) ? data.data.length : 0;
            console.log(`[net] getDetalle recibido, keys: ${Object.keys(data)}, filas: ${filas}`);
          } catch (e) {
            console.warn("[net] getDetalle no-JSON:", (e as Error).message);
          }
        }
      }
    };
    page.on("response", onResponse);

    // 2. Navegar al portal RCV
    await page.goto("https://www4.sii.cl/consdcvinternetui/", {
      waitUntil: "domcontentloaded",
      timeout: PAGE_TIMEOUT_MS,
    });

    await page.waitForSelector("#periodoMes", { timeout: PAGE_TIMEOUT_MS });
    // El listener ya captura getDcvEmpresasAutorizadas; polling evita la race condition
    await pollUntil(() => empresasAutorizadasReceived, PAGE_TIMEOUT_MS, "getDcvEmpresasAutorizadas");
    await new Promise((r) => setTimeout(r, 500));

    // 3. Setear período deseado
    await page.select("#periodoMes", month.padStart(2, "0"));
    await page.select('select[ng-model="periodoAnho"]', year);
    const [mesVal, anhoVal] = await page.evaluate(() => {
      const m = document.querySelector("#periodoMes") as HTMLSelectElement;
      const a = document.querySelector('select[ng-model="periodoAnho"]') as HTMLSelectElement;
      return [m?.value, a?.value];
    });
    console.log(`[fetchRCV] período en form: mes=${mesVal} año=${anhoVal}`);
    await new Promise((r) => setTimeout(r, 500));

    // 4. Primera consulta (tab COMPRA activo por defecto)
    console.log("[fetchRCV] clickeando Consultar...");
    await page.click('button[type="submit"]');

    await pollUntil(() => resumenResponses.length >= 1, PAGE_TIMEOUT_MS, "primera getResumen");
    console.log(`[fetchRCV] primera getResumen recibida`);

    // Esperar a que el DOM renderice los resultados
    await page.waitForFunction(
      () => document.body.innerText.includes("RESUMEN REGISTRO"),
      { timeout: PAGE_TIMEOUT_MS }
    );
    await new Promise((r) => setTimeout(r, 500));

    // 5. Para ventas: cambiar al tab VENTA
    let summaryRaw: Record<string, unknown>;

    if (mode === "ventas") {
      const baselineCount = resumenResponses.length;

      const tabText = await page.evaluate(() => {
        const tabs = Array.from(document.querySelectorAll(".nav-tabs a, .nav-tabs li a"));
        const tab = tabs.find((t) => /venta/i.test(t.textContent?.trim() ?? ""));
        if (tab) { (tab as HTMLElement).click(); return tab.textContent?.trim(); }
        return null;
      });

      if (!tabText) throw new Error("Tab VENTA no encontrado en el DOM");
      console.log(`[fetchRCV] tab VENTA clickeado: "${tabText}"`);

      const gotAuto = await pollUntil(() => resumenResponses.length > baselineCount, 8_000, "")
        .then(() => true).catch(() => false);

      if (!gotAuto) {
        console.log("[fetchRCV] tab VENTA no disparó getResumen automático, haciendo segundo Consultar");
        await page.click('button[type="submit"]');
        await pollUntil(() => resumenResponses.length > baselineCount, PAGE_TIMEOUT_MS, "segunda getResumen (VENTA)");
      } else {
        console.log("[fetchRCV] tab VENTA disparó getResumen automáticamente");
      }

      summaryRaw = resumenResponses[resumenResponses.length - 1];
      console.log(`[fetchRCV] VENTA getResumen, keys: ${Object.keys(summaryRaw)}`);
      await new Promise((r) => setTimeout(r, 1500));
    } else {
      summaryRaw = resumenResponses[0];
      console.log(`[fetchRCV] COMPRA getResumen, keys: ${Object.keys(summaryRaw)}`);
    }

    const summaries = parseRcvSummaryFromJson(summaryRaw, operacion);

    // 6. Si se piden detalles, hacer clic en "Descargar Detalles"
    const clickDescargarDetalles = () => page.evaluate(() => {
      const isDetalles = (b: Element) => /descargar\s*det/i.test(b.textContent?.trim() ?? "");
      const allBtns = Array.from(document.querySelectorAll("button"));
      const activePane = document.querySelector(".tab-pane.active");
      if (activePane) {
        const btn = Array.from(activePane.querySelectorAll("button")).find(isDetalles);
        if (btn) { (btn as HTMLButtonElement).click(); return "active-pane"; }
      }
      const visible = allBtns.find((b) => isDetalles(b) && (b as HTMLElement).offsetParent !== null);
      if (visible) { visible.click(); return "visible"; }
      const any = allBtns.find(isDetalles);
      if (any) { any.click(); return "any"; }
      return null;
    });

    let detalles: object[] = [];
    if (detallado) {
      for (let intento = 1; intento <= 3; intento++) {
        detalleRaw = null;
        detalleStatus = 0;

        const clickResult = await clickDescargarDetalles();
        console.log(`[fetchRCV] intento ${intento}: clickDescargarDetalles → ${clickResult}`);
        if (!clickResult) throw new Error("No se encontró el botón 'Descargar Detalles' en el portal SII.");

        await pollUntil(() => detalleStatus !== 0, PAGE_TIMEOUT_MS, `getDetalle intento ${intento}`);
        console.log(`[fetchRCV] intento ${intento}: detalleStatus=${detalleStatus}`);

        if (detalleRaw) break;

        console.warn(`[fetchRCV] SII devolvió ${detalleStatus} en getDetalle (intento ${intento})`);
        if (intento < 3) await new Promise((r) => setTimeout(r, 3000));
      }

      if (!detalleRaw) throw new Error("El SII devolvió error al obtener los detalles. Reintente en unos minutos.");
      detalles = parseRcvDetailsFromJson(detalleRaw, operacion);
    }

    // 7. Construir respuesta
    const monthNames = ["---", "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
      "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"];

    const caratula = {
      rutEmpresa: `${rutNum}-${dv}`,
      nombreMes:  monthNames[parseInt(month)],
      mes:        month,
      anio:       year,
      periodo:    ptributario,
    };

    if (operacion === "COMPRA") {
      return { caratula, compras: { resumenes: summaries, detalleCompras: detalles } };
    }
    return { caratula, ventas: { resumenes: summaries, detalleVentas: detalles } };

  } finally {
    if (onResponse) page.off("response", onResponse);
  }
}

// ─── Lógica Boletas de Honorarios (recibidas) ────────────────────────────────

const ESTADO_BHE_MAP: Record<string, string> = {
  N: "VIGENTE",
  S: "ANULADA",
  V: "VIGENTE_ANULACION_PENDIENTE",
  R: "OBSERVADA_RECEPTOR",
  U: "OBSERVADA_UNIDAD",
};

function parseMontoBHE(v: unknown): number {
  return Number(String(v ?? "0").replace(/\./g, "")) || 0;
}

interface BoletaRecibidaRaw {
  folio: string;
  estado: string;
  fechaAnulacion: string;
  fecha: string;
  rutEmisor: string;
  nombreEmisor: string;
  sociedadProfesional: boolean;
  montoBruto: string;
  montoRetenido: string;
  montoLiquido: string;
}

interface InformeMensualBHE {
  rut: string;
  contribuyente: string;
  totalBoletas: string;
  totalHonorarios: string;
  totalRetencion: string;
  totalLiquido: string;
  paginaActual: string;
  boletas: BoletaRecibidaRaw[];
}

// El informe se renderiza en el cliente vía document.write() a partir de variables
// globales (xml_values / arr_informe_mensual) inyectadas por el SII en un <script>.
// Leerlas directamente evita parsear el HTML/tablas ya renderizadas.
function extractInformeMensualBHE(page: Page): Promise<InformeMensualBHE> {
  return page.evaluate(() => {
    const xv = (window as any).xml_values ?? {};
    const arr = (window as any).arr_informe_mensual ?? {};
    const cantidadFilas = Number((window as any).CantidadFilas || 0);
    const boletas = [];
    for (let i = 1; i <= cantidadFilas; i++) {
      boletas.push({
        folio: arr["nroboleta_" + i],
        estado: arr["estado_" + i],
        fechaAnulacion: (arr["fechaanulacion_" + i] || "").trim(),
        fecha: arr["fecha_boleta_" + i],
        rutEmisor: `${arr["rutemisor_" + i]}-${arr["dvemisor_" + i]}`,
        nombreEmisor: (arr["nombre_emisor_" + i] || "").trim(),
        sociedadProfesional: arr["es_soc_profesional_" + i] === "SI",
        montoBruto: arr["totalhonorarios_" + i],
        montoRetenido: arr["retencion_receptor_" + i],
        montoLiquido: arr["honorariosliquidos_" + i],
      });
    }
    return {
      rut: `${xv["rut_arrastre"]}-${xv["dv_arrastre"]}`,
      contribuyente: xv["nombre_contribuyente"],
      totalBoletas: xv["total_boletas"],
      totalHonorarios: xv["suma_honorarios"],
      totalRetencion: xv["suma_retencion_receptor"],
      totalLiquido: xv["suma_liquido"],
      paginaActual: xv["pagina_actual"],
      boletas,
    };
  });
}

async function fetchBoletasHonorariosRecibidas(
  month: string,
  year: string,
  user: string,
  pass: string
): Promise<object> {
  return conSesionSii("boletas honorarios", user, pass, (page) =>
    descargarBHE(page, month, year)
  );
}

// Descarga el informe mensual de BHE recibidas con una página ya autenticada.
async function descargarBHE(page: Page, month: string, year: string): Promise<object> {
  await page.goto(
    `https://loa.sii.cl/cgi_IMT/TMBCOC_MenuConsultasContribRec.cgi?dummy=${Date.now()}`,
    { waitUntil: "domcontentloaded", timeout: PAGE_TIMEOUT_MS }
  );
  await page.waitForSelector("select[name='cbmesinformemensual']", { timeout: PAGE_TIMEOUT_MS });
  await page.select("select[name='cbmesinformemensual']", month.padStart(2, "0"));
  await page.select("select[name='cbanoinformemensual']", year);

  await Promise.all([
    page.waitForNavigation({ timeout: PAGE_TIMEOUT_MS }),
    page.click('input[name="cmdconsultar1"][onclick*="validar_mensual"]'),
  ]);
  await page.waitForFunction(() => typeof (window as any).xml_values !== "undefined", {
    timeout: PAGE_TIMEOUT_MS,
  });

  let informe = await extractInformeMensualBHE(page);
  const boletasRaw: BoletaRecibidaRaw[] = [...informe.boletas];

  // El SII pagina de a 100 filas (MAXFILAS); listar(n) es la función embebida
  // en la página que resubmite el formulario pidiendo la página n.
  const totalPaginas = Math.ceil((Number(informe.totalBoletas) || 0) / 100) || 1;
  while (Number(informe.paginaActual) < totalPaginas) {
    const siguiente = Number(informe.paginaActual) + 1;
    await Promise.all([
      page.waitForNavigation({ timeout: PAGE_TIMEOUT_MS }),
      page.evaluate((p) => (window as any).listar(p), siguiente),
    ]);
    await page.waitForFunction(() => typeof (window as any).xml_values !== "undefined", {
      timeout: PAGE_TIMEOUT_MS,
    });
    informe = await extractInformeMensualBHE(page);
    boletasRaw.push(...informe.boletas);
  }

  const boletas = boletasRaw.map((b) => ({
    folio: b.folio,
    estado: ESTADO_BHE_MAP[b.estado] ?? b.estado,
    fechaAnulacion: b.fechaAnulacion || null,
    fecha: b.fecha,
    rutEmisor: b.rutEmisor,
    nombreEmisor: b.nombreEmisor,
    sociedadProfesional: b.sociedadProfesional,
    montoBruto: parseMontoBHE(b.montoBruto),
    montoRetenido: parseMontoBHE(b.montoRetenido),
    montoLiquido: parseMontoBHE(b.montoLiquido),
  }));

  return {
    caratula: {
      rutContribuyente: informe.rut,
      nombreContribuyente: informe.contribuyente,
      mes: month,
      anio: year,
    },
    resumen: {
      totalBoletas: Number(informe.totalBoletas) || 0,
      totalHonorarios: parseMontoBHE(informe.totalHonorarios),
      totalRetencion: parseMontoBHE(informe.totalRetencion),
      totalLiquido: parseMontoBHE(informe.totalLiquido),
    },
    boletas,
  };
}

// Informe anual de BHE recibidas: una sola consulta con el resumen de los 12 meses. Los datos
// vienen en window.xml_values con un sufijo por columna: 1 = honorario bruto, 2 = retención de
// terceros, 3 = retención del contribuyente, 6 = boletas vigentes, 7 = boletas anuladas y
// sum<mes> = total líquido. (1, 2, 6 y sum están contrastados con un mes con datos; 3 y 7 se
// leen por posición en la tabla pero estaban vacíos en la cuenta de prueba.)
const MESES_BHE = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];

async function descargarBHEAnual(page: Page, year: string): Promise<object> {
  await page.goto(
    `https://loa.sii.cl/cgi_IMT/TMBCOC_MenuConsultasContribRec.cgi?dummy=${Date.now()}`,
    { waitUntil: "domcontentloaded", timeout: PAGE_TIMEOUT_MS }
  );
  await page.waitForSelector("select[name='cbanoinformeanual']", { timeout: PAGE_TIMEOUT_MS });
  await page.select("select[name='cbanoinformeanual']", year);
  await Promise.all([
    page.waitForNavigation({ timeout: PAGE_TIMEOUT_MS }),
    page.click('input[name="cmdconsultar12"]'),
  ]);
  await page.waitForFunction(() => typeof (window as any).xml_values !== "undefined", {
    timeout: PAGE_TIMEOUT_MS,
  });
  const xv = await page.evaluate(() => {
    const src = (window as any).xml_values as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const k of Object.keys(src)) out[k] = String(src[k] ?? "");
    return out;
  });

  const meses = MESES_BHE.map((m, i) => ({
    mes: i + 1,
    boletasVigentes: Number(xv[`${m}6`]) || 0,
    boletasAnuladas: Number(xv[`${m}7`]) || 0,
    honorarioBruto: parseMontoBHE(xv[`${m}1`]),
    retencionTerceros: parseMontoBHE(xv[`${m}2`]),
    retencionContribuyente: parseMontoBHE(xv[`${m}3`]),
    totalLiquido: parseMontoBHE(xv[`sum${m}`]),
  }));
  return {
    anio: Number(xv["anio_consulta"]) || Number(year),
    contribuyente: { rut: `${xv["rut_arrastre"]}-${xv["dv_arrastre"]}`, nombre: xv["nombre_contribuyente"] },
    meses,
    totales: {
      boletasVigentes: Number(xv["tot6"]) || 0,
      boletasAnuladas: Number(xv["tot7"]) || 0,
      honorarioBruto: parseMontoBHE(xv["tot1"]),
      retencionTerceros: parseMontoBHE(xv["tot2"]),
      retencionContribuyente: parseMontoBHE(xv["tot3"]),
      totalLiquido: parseMontoBHE(xv["sumtot"]),
    },
    origen: {
      servicio: "https://loa.sii.cl/cgi_IMT/TMBCOC_InformeAnualBheRec.cgi (informe anual BHE recibidas)",
      descargado: new Date().toISOString(),
    },
  };
}

// ─── Validación ──────────────────────────────────────────────────────────────

const RUT_REGEX   = /^\d{1,8}-[\dkK]$/;
const MONTH_REGEX = /^(0?[1-9]|1[0-2])$/;
const YEAR_REGEX  = /^(19|20)\d{2}$/;

function validateRcvParams(month: string, year: string, res: Response): boolean {
  if (!MONTH_REGEX.test(month)) {
    res.status(400).json({ error: "Mes inválido. Use un valor entre 1 y 12." });
    return false;
  }
  if (!YEAR_REGEX.test(year)) {
    res.status(400).json({ error: "Año inválido. Use un año de 4 dígitos." });
    return false;
  }
  return true;
}

function getRcvCredentialsFromBody(
  body: { rut?: string; pass?: string },
  res: Response
): { user: string; pass: string } | null {
  const { rut, pass } = body;
  if (!rut || !pass) {
    res.status(400).json({ error: "Se requieren los campos 'rut' y 'pass' en el body." });
    return null;
  }
  if (!RUT_REGEX.test(rut)) {
    res.status(400).json({ error: "Formato de RUT inválido. Use el formato: 12345678-9" });
    return null;
  }
  return { user: rut, pass };
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

async function fetchEstadoF29(rut: string, pass: string): Promise<object> {
  return conSesionSii("F29", rut, pass, async (page) => {
    await page.goto(
      "https://www4.sii.cl/sifmConsultaInternet/index.html?dest=cifxx&form=29",
      { waitUntil: "load", timeout: PAGE_TIMEOUT_MS }
    );
    await page.waitForSelector(".gw-formulario-base-celda", { timeout: PAGE_TIMEOUT_MS });

    const button = await page.$("table a");
    if (button) await button.click();

    const html = await page.content();
    const d = parse(html);
    const tableHeader = d.querySelectorAll(
      "#frame-window > table > tbody > tr:nth-child(2) > td > table > tbody > tr > td > div > table:nth-child(5) > tbody > tr > td:nth-child(2) > table > tbody > tr:nth-child(1) > td > table > tbody > tr:nth-child(1) > td > table > tbody > tr:nth-child(3) > td > table > tbody > tr:nth-child(1) > td > table > tbody > tr:nth-child(2) td"
    );
    const tableData = d.querySelectorAll(
      "#frame-window > table > tbody > tr:nth-child(2) > td > table > tbody > tr > td > div > table:nth-child(5) > tbody > tr > td:nth-child(2) > table > tbody > tr:nth-child(1) > td > table > tbody > tr:nth-child(1) > td > table > tbody > tr:nth-child(3) > td > table > tbody > tr:nth-child(2) > td > table > tbody > tr > td > table > tbody > tr > td:nth-child(2) > table > tbody > tr"
    );

    const data: { year: string; months: { month: string; message: string }[] }[] = [];
    for (const header of tableHeader) {
      const dr = header.querySelector(".gw-par");
      if (dr != null) {
        data.push({ year: dr.childNodes[0].innerText, months: [] });
      }
    }
    for (const row of tableData) {
      const td = row.querySelectorAll("td");
      let ddl = row
        .querySelectorAll(".tooltip")
        .reverse()
        .map((item: any) => item.innerText);
      if (data.length > ddl.length) {
        ddl = [...ddl, ...Array(data.length - ddl.length).fill("--")];
      }
      ddl = ddl.reverse();
      for (let j = data.length - 1; j >= 0; j--) {
        data[j].months.push({ month: td[0].innerText, message: ddl[j] });
      }
    }

    return { data };
  });
}

// ─── Declaración F29 de un período (app propuestaf29ui) ──────────────────────

const F29_APP_URL = "https://www4.sii.cl/propuestaf29ui/internet/";
const F29_NS = "cl.sii.sdi.lob.iva.propuestaf29.data.api.interfaces";

interface F29Envelope<T> {
  data: T;
  metaData?: { errors?: unknown };
  respCod?: number | null;
  errorMsg?: string | null;
}

// Llama a un servicio JSON (envelope {metaData, data}) de una app del SII desde el contexto
// de la página, con las cookies de sesión. La página debe estar ya en el origen de la app.
async function llamarServicioSii<T>(
  page: Page,
  url: string,
  namespace: string,
  method: string,
  data: Record<string, unknown>
): Promise<T> {
  const run = () => page.evaluate(
    async (u, ns, payload) => {
      const body = {
        metaData: {
          namespace: ns,
          conversationId: `X${Math.random().toString(36).slice(2, 12).toUpperCase()}`,
          transactionId: crypto.randomUUID(),
        },
        data: payload,
      };
      const r = await fetch(u, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
        credentials: "include",
      });
      return { status: r.status, text: await r.text() };
    },
    url,
    namespace,
    data
  );
  let result: { status: number; text: string };
  try {
    result = await run();
  } catch {
    await new Promise((r) => setTimeout(r, 3_000));
    result = await run();
  }
  if (result.status !== 200) {
    throw new Error(`El SII respondió ${result.status} en ${method}`);
  }
  let parsed: F29Envelope<T>;
  try {
    parsed = JSON.parse(result.text) as F29Envelope<T>;
  } catch {
    throw new Error(`Respuesta no válida del SII en ${method}`);
  }
  if (parsed.metaData?.errors || parsed.respCod === -1) {
    throw new Error(`El SII devolvió un error en ${method}${parsed.errorMsg ? `: ${parsed.errorMsg}` : ""}`);
  }
  return parsed.data;
}

// App propuestaf29ui: las rutas usan la inicial en minúscula (facadeAdapterService) y el
// namespace en mayúscula.
function callF29Service<T>(
  page: Page,
  service: string,
  method: string,
  data: Record<string, unknown>
): Promise<T> {
  return llamarServicioSii<T>(
    page,
    `/propuestaf29ui/services/data/${service.charAt(0).toLowerCase()}${service.slice(1)}/${method}`,
    `${F29_NS}.${service}/${method}`,
    method,
    data
  );
}

interface F29DeclaracionRaw {
  estado: string;
  monto: number;
  folio: number;
  codigo: number;
  declFechaCreacion: string;
}

interface F29TasaPpmRaw {
  cod563: string | null;
  esPropyme: boolean;
}

function toNumberOrNull(v: string | null | undefined): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

async function fetchDeclaracionF29(rut: string, pass: string, month: string, year: string): Promise<object> {
  return conSesionSii("declaración F29", rut, pass, async (page) => {
    await page.goto(F29_APP_URL, { waitUntil: "load", timeout: PAGE_TIMEOUT_MS });
    if (!page.url().includes("propuestaf29ui")) {
      throw new Error("No se pudo abrir la aplicación de declaración F29 del SII (posible cola de espera).");
    }

    // La SPA sigue redirigiendo internamente tras el login; un fetch lanzado antes de que
    // se asiente falla con "Failed to fetch".
    await page.waitForNetworkIdle({ idleTime: 1_500, timeout: 20_000 }).catch(() => {});

    const [num, dv] = rut.split("-");
    const mes = String(Number(month));
    const anno = String(year);

    const declaraciones = await callF29Service<F29DeclaracionRaw[] | null>(
      page, "FacadeAdapterService", "getDeclaracionConEstados",
      { rut: num, dv, formId: "2", mes, anno }
    );
    const ppm = await callF29Service<F29TasaPpmRaw | null>(
      page, "FacadeAdapterService", "getTasaPPMO",
      { rutContribuyente: num, dv, mes, anno, categoriaTributaria: 1, tipoFormulario: "FMNINT" }
    );

    const lista = Array.isArray(declaraciones) ? declaraciones : [];
    return {
      periodo: `${anno}${mes.padStart(2, "0")}`,
      estado: lista.length > 0 ? "declarado" : "sinDeclaracion",
      declaraciones: lista.map((d) => ({
        estado: d.estado,
        monto: d.monto,
        folio: d.folio,
        fechaDeclaracion: d.declFechaCreacion,
      })),
      ppm: {
        // No se expone la tasa: cod115 de getTasaPPMO (0,1) no coincide con la tasa
        // realmente declarada (1%, código 115 del detalle del F29).
        baseVentasNetas: toNumberOrNull(ppm?.cod563),
        esPropyme: ppm?.esPropyme ?? null,
      },
    };
  });
}

// ─── Detalle por código del F29 vigente (portal rfiInternet/consulta, GWT) ───

const F29_CONSULTA_URL = "https://www4.sii.cl/rfiInternet/consulta/index.html";
const MESES_ES = ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto",
  "Septiembre", "Octubre", "Noviembre", "Diciembre"];

class SinDeclaracionError extends Error {}

// "1.753.554" → 1753554 ; "0,25" → 0.25
function parseMontoSii(v: string): number | null {
  const n = Number(v.replace(/\./g, "").replace(",", "."));
  return Number.isFinite(n) ? n : null;
}

// "07/10/2026 17:09:29" → "2026-10-07"
function fechaSiiAIso(v: string): string | null {
  const m = /^(\d{2})\/(\d{2})\/(\d{4})/.exec(v);
  return m ? `${m[3]}-${m[2]}-${m[1]}` : null;
}

// Formulario compacto en PDF (el que abre el botón "Formulario Compacto" de la Consulta Integral),
// como evidencia. La página debe estar en www4.sii.cl para que la petición vaya con la sesión.
// Si el SII no devuelve un PDF se omite (devuelve null) sin tumbar la descarga principal.
async function descargarFormCompactoPdf(
  page: Page,
  rut: string,
  folio: number,
  codigoInterno: number,
  form: string,
  nombre: string
): Promise<{ nombre: string; sha256: string; base64: string } | null> {
  try {
    const url = `https://www4.sii.cl/rfiInternet/formCompacto?folio=${folio}&rut=${rut.split("-")[0]}&form=${form}&codInt=${codigoInterno}`;
    const r = await page.evaluate(async (u: string) => {
      const resp = await fetch(u, { credentials: "include" });
      const bytes = new Uint8Array(await resp.arrayBuffer());
      let bin = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      }
      return { status: resp.status, tipo: resp.headers.get("content-type") ?? "", base64: btoa(bin) };
    }, url);
    const buffer = Buffer.from(r.base64, "base64");
    if (r.status !== 200 || !r.tipo.includes("pdf") || buffer.subarray(0, 4).toString() !== "%PDF") {
      console.warn(`[formCompacto] el SII no devolvió un PDF (HTTP ${r.status}, ${r.tipo || "sin tipo"}).`);
      return null;
    }
    return { nombre, sha256: createHash("sha256").update(buffer).digest("hex"), base64: r.base64 };
  } catch (e) {
    console.warn("[formCompacto] no se pudo descargar el PDF:", (e as Error).message);
    return null;
  }
}

// Descarga el detalle del F29 vigente con una página ya autenticada. El portal es una
// app GWT (RPC serializado), así que se maneja la interfaz: formulario → período →
// Buscar → folio → "Ver Datos", y se leen los pares código/valor del formulario en
// pantalla. Nunca se pulsa "Rectificar".
async function descargarF29Detalle(page: Page, rut: string, month: string, year: string): Promise<object> {
  const mes = String(Number(month));
  const [num, dv] = rut.split("-");

  // Historial de declaraciones del período (app propuestaf29ui).
  await page.goto(F29_APP_URL, { waitUntil: "load", timeout: PAGE_TIMEOUT_MS });
  if (!page.url().includes("propuestaf29ui")) {
    throw new Error("No se pudo abrir la aplicación de declaración F29 del SII (posible cola de espera).");
  }
  await page.waitForNetworkIdle({ idleTime: 1_500, timeout: 20_000 }).catch(() => {});
  const declaraciones = await callF29Service<F29DeclaracionRaw[] | null>(
    page, "FacadeAdapterService", "getDeclaracionConEstados",
    { rut: num, dv, formId: "2", mes, anno: year }
  );
  const lista = Array.isArray(declaraciones) ? declaraciones : [];
  if (!lista.some((d) => /vigente/i.test(d.estado))) {
    throw new SinDeclaracionError(`No hay declaración F29 vigente para el período ${year}-${mes.padStart(2, "0")}.`);
  }

  // Portal de consulta: seleccionar formulario y período, y buscar.
  await page.goto(F29_CONSULTA_URL, { waitUntil: "load", timeout: PAGE_TIMEOUT_MS });
  await page.waitForSelector("select", { timeout: PAGE_TIMEOUT_MS });
  // Al cambiar el año el portal rehace la lista de meses (vuelve al mes actual), por eso
  // se espera entre cada cambio y se verifica el resultado antes de buscar.
  const pausa = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const elegir = async (texto: string) => {
    for (const sel of await page.$$("select")) {
      const valor = await sel.evaluate(
        (s, t) => Array.from(s.options).find((o) => o.text.trim() === t)?.value ?? null,
        texto
      );
      if (valor !== null) {
        await sel.select(valor);
        await pausa(1_500);
        return;
      }
    }
    throw new Error(`Opción no encontrada en el portal SII: ${texto}`);
  };
  const mesNombre = MESES_ES[Number(mes) - 1];
  await elegir("Formulario 29");
  await elegir(year);
  await elegir(mesNombre);
  const elegidos = await page.evaluate(() =>
    Array.from(document.querySelectorAll("select")).map((s) => s.options[s.selectedIndex].text.trim())
  );
  if (!elegidos.includes(year) || !elegidos.includes(mesNombre)) {
    throw new Error(`El portal SII no conservó el período seleccionado (${elegidos.join(" | ")}).`);
  }
  // El clic simulado por Puppeteer no activa este botón GWT; click() desde la página sí.
  await page.evaluate(() => {
    const boton = Array.from(document.querySelectorAll("button")).find((b) =>
      /Buscar Datos Ingresados/.test(b.textContent ?? "")
    );
    if (!boton) throw new Error("No se encontró el botón de búsqueda del portal SII.");
    boton.click();
  });
  await page.waitForFunction(
    () => document.body.innerText.includes("DECLARACIONES VIGENTES"),
    { timeout: PAGE_TIMEOUT_MS }
  );

  // Folio vigente: primer enlace numérico de la tabla de resultados.
  const linkHandle = await page.evaluateHandle(() =>
    Array.from(document.querySelectorAll("a")).find((a) => /^\d{8,}$/.test(a.textContent?.trim() ?? "")) ?? null
  );
  const link = linkHandle.asElement();
  if (!link) throw new SinDeclaracionError("El portal SII no listó declaraciones vigentes para el período.");
  const folio = Number((await link.evaluate((a) => a.textContent ?? "")).trim());
  await (link as unknown as { click(): Promise<void> }).click();

  await page.locator("::-p-text(Ver Datos)").setTimeout(PAGE_TIMEOUT_MS).click();
  await page.waitForFunction(
    () => document.body.innerText.includes("TOTAL A PAGAR DENTRO DEL PLAZO LEGAL"),
    { timeout: PAGE_TIMEOUT_MS }
  );

  // Pares código/valor del formulario. Cada fila trae [nº línea] [etiqueta] y pares
  // (código, valor); los códigos sin valor no se muestran (valen 0). Se ignoran las
  // filas del glosario porque su "valor" es texto.
  const crudos = await page.evaluate(() => {
    // Códigos del 16 en adelante: 1–15 son la carátula (la fila del período, p. ej. mes 10 con
    // el año como valor, se leería como un código si no se excluyera).
    const isCode = (t: string) => /^(1[6-9]|[2-9]\d|[1-9]\d{2,3})$/.test(t);
    const isNum = (t: string) => /^-?\d{1,3}(\.\d{3})*(,\d+)?$|^-?\d+(,\d+)?$/.test(t);
    const out: Record<string, string> = {};
    const rows = Array.from(document.querySelectorAll("tr")).filter((r) => !r.querySelector("tr"));
    for (const r of rows) {
      const cells = Array.from(r.children).map((c) => {
        const input = c.querySelector("input");
        return input ? input.value.trim() : (c as HTMLElement).innerText.trim().replace(/\s+/g, " ");
      });
      let start = 0;
      if (cells.length >= 3 && /^\d{1,2}$/.test(cells[0]) && cells[1].length > 3 && !isCode(cells[1])) start = 2;
      else if (cells.length >= 2 && !isCode(cells[0]) && cells[0].length > 3) start = 1;
      for (let k = start; k < cells.length - 1; k++) {
        if (isCode(cells[k]) && isNum(cells[k + 1])) {
          out[cells[k]] = cells[k + 1];
          k++;
        }
      }
    }
    return out;
  });
  const codigos: Record<string, number> = {};
  for (const [codigo, valor] of Object.entries(crudos)) {
    const n = parseMontoSii(valor);
    if (n !== null) codigos[codigo] = n;
  }

  const vigente = lista.find((d) => /vigente/i.test(d.estado))!;
  const anteriores = lista.filter((d) => d !== vigente);
  // Solo cuenta como rectificatoria si reemplazó a otra declaración que llegó a estar vigente:
  // una declaración "rechazada por pago inconcluso" nunca fue vigente (inferido del estado).
  const reemplazo = anteriores.some((d) => /reemplaz|rectific/i.test(d.estado));
  const archivo = await descargarFormCompactoPdf(
    page, rut, folio, vigente.codigo, "029", `F29_${rut}_${year}-${mes.padStart(2, "0")}_${folio}.pdf`
  );
  return {
    periodo: `${year}-${mes.padStart(2, "0")}`,
    vigente: {
      folio,
      fechaDeclaracion: fechaSiiAIso(vigente.declFechaCreacion),
      tipo: reemplazo ? "rectificatoria" : "original",
    },
    codigos,
    ...(archivo ? { archivo } : {}),
    historial: anteriores.map((d) => ({
      folio: d.folio,
      fecha: fechaSiiAIso(d.declFechaCreacion),
      estado: d.estado.toLowerCase(),
    })),
    origen: {
      servicio: `${F29_CONSULTA_URL} (Formulario 29 → Ver Datos)`,
      descargado: new Date().toISOString(),
    },
  };
}

app.post("/api/F29/detalle/:month/:year", requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
  const { month, year } = req.params;
  if (!validateRcvParams(month, year, res)) return;
  const creds = getRcvCredentialsFromBody(req.body, res);
  if (!creds) return;
  if (!checkRutCooldown(creds.user, res)) return;
  try {
    const data = await withTimeout(
      conSesionSii("detalle F29", creds.user, creds.pass, (page) =>
        descargarF29Detalle(page, creds.user, month, year)
      ),
      REQUEST_TIMEOUT_MS,
      "consulta detalle F29"
    );
    res.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    console.error("[/api/F29/detalle] Error:", message);
    const status = err instanceof SinDeclaracionError ? 404 : message.includes("inválidas") ? 401 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── F22 (consultaestadof22ui) y estado de DDJJ (djconsulta) ─────────────────

const F22_APP_URL = "https://www4.sii.cl/consultaestadof22ui/";
const F22_NS = "cl.sii.sdi.lob.renta.consultaestadof22.data.api.interfaces.FacadeService";
const DDJJ_CONSULTA_URL = "https://www2.sii.cl/djconsulta/consultaddjjs";

function callF22Service<T>(page: Page, method: string, data: Record<string, unknown>): Promise<T> {
  return llamarServicioSii<T>(
    page,
    `/consultaestadof22ui/services/data/facadeService/${method}`,
    `${F22_NS}/${method}`,
    method,
    data
  );
}

interface F22FolioRaw {
  folio: number;
  fecIng: string;
  vgte: string | null;
  evigCodigo: string;
  rectificacble: string | null;
}

interface F22EventoRaw {
  codEvento: string;
  nombre: string;
  fechaEvento: string;
}

const pausa = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Abre la app del F22 y localiza el folio vigente del año tributario `at`.
async function abrirConsultaF22(
  page: Page,
  rut: string,
  at: string
): Promise<{ vigente: F22FolioRaw; folios: F22FolioRaw[] }> {
  await page.goto(F22_APP_URL, { waitUntil: "load", timeout: PAGE_TIMEOUT_MS });
  await page.waitForNetworkIdle({ idleTime: 2_000, timeout: 20_000 }).catch(() => {});
  const [num, dv] = rut.split("-");
  const folios = await callF22Service<F22FolioRaw[] | null>(page, "consultaFolios", {
    rut: num,
    dv,
    periodo: Number(at),
    pathRuta: "/consultaEstadoDecIni",
  });
  const lista = Array.isArray(folios) ? folios : [];
  const vigente = lista.find((f) => f.vgte === "1");
  if (!vigente) throw new SinDeclaracionError(`No hay F22 vigente para el año tributario ${at}.`);
  return { vigente, folios: lista };
}

// Estado del F22 de un año tributario: folio vigente, historial de eventos y observaciones.
async function descargarF22Estado(page: Page, rut: string, at: string): Promise<object> {
  const { vigente, folios } = await abrirConsultaF22(page, rut, at);
  const [num, dv] = rut.split("-");
  const observaciones = await callF22Service<unknown[] | null>(page, "situacionObservacion", {
    periodo: Number(at), rut: num, dv, folio: vigente.folio,
  });
  const eventos = await callF22Service<F22EventoRaw[] | null>(page, "buscaEventos", {
    periodo: Number(at), rut: num, dv, folio: vigente.folio, impugnado: "0", evigCodigo: vigente.evigCodigo,
  });
  const historial = (Array.isArray(eventos) ? eventos : []).map((e) => ({
    fecha: fechaSiiAIso(e.fechaEvento),
    codigo: e.codEvento,
    descripcion: e.nombre,
  }));
  return {
    at: Number(at),
    vigente: {
      folio: vigente.folio,
      fechaIngreso: fechaSiiAIso(vigente.fecIng),
      rectificable: vigente.rectificacble === "1",
      estadoCodigo: vigente.evigCodigo,
    },
    ultimoEvento: historial.length > 0 ? historial[historial.length - 1] : null,
    historial,
    // Observaciones vigentes tal como las entrega el SII (vacío si no hay ninguna).
    observaciones: Array.isArray(observaciones) ? observaciones : [],
    otrosFolios: folios
      .filter((f) => f !== vigente)
      .map((f) => ({ folio: f.folio, fechaIngreso: fechaSiiAIso(f.fecIng) })),
    origen: { servicio: `${F22_APP_URL} (consultaFolios, situacionObservacion, buscaEventos)`, descargado: new Date().toISOString() },
  };
}

// Detalle por código del F22 vigente. La app muestra el formulario completo en HTML y cada
// campo es un <input id="COD_xxx">: se leen por id. Nunca se pulsa "Rectificar".
async function descargarF22Detalle(page: Page, rut: string, at: string): Promise<object> {
  const { vigente } = await abrirConsultaF22(page, rut, at);

  const sel = await page.$("select");
  if (!sel) throw new Error("No se encontró el selector de año tributario del portal SII.");
  const valor = await sel.evaluate(
    (s, t) => Array.from(s.options).find((o) => o.text.trim() === t)?.value ?? null,
    at
  );
  if (valor === null) throw new SinDeclaracionError(`El portal SII no ofrece el año tributario ${at}.`);
  await sel.select(valor);
  await pausa(1_500);
  await page.evaluate(() => {
    const b = Array.from(document.querySelectorAll("button")).find((x) => (x.textContent ?? "").trim() === "Consultar");
    if (!b) throw new Error("No se encontró el botón Consultar del portal SII.");
    b.click();
  });
  await page.waitForFunction(
    () => Array.from(document.querySelectorAll("a,button")).some((e) => (e.textContent ?? "").trim() === "Formulario 22"),
    { timeout: PAGE_TIMEOUT_MS }
  );
  await page.evaluate(() => {
    const e = Array.from(document.querySelectorAll("a,button")).find((x) => (x.textContent ?? "").trim() === "Formulario 22");
    (e as HTMLElement).click();
  });
  // El formulario se rellena de forma asíncrona: esperar a que el folio esté cargado.
  await page.waitForFunction(
    () => ((document.querySelector("#FOLIO_PRM") as HTMLInputElement | null)?.value ?? "").trim() !== "",
    { timeout: PAGE_TIMEOUT_MS }
  );
  await pausa(1_000);

  // El código sale de ng-model="formulario.declaracion.cod###" (el id unas veces es COD_### y
  // otras solo el número). Se ignoran los checkboxes y los campos sin valor.
  const crudos = await page.evaluate(() => {
    const out: [string, string][] = [];
    for (const i of Array.from(document.querySelectorAll("input")) as HTMLInputElement[]) {
      const v = i.value.trim();
      if (v === "" || v === "on" || v === "off") continue;
      const m = /\.cod(\d+)$/.exec(i.getAttribute("ng-model") ?? "") ?? /^(?:COD_)?(\d{1,5})$/.exec(i.id);
      if (m) out.push([m[1], v]);
    }
    return out;
  });
  const codigos: Record<string, number> = {};
  const codigosTexto: Record<string, string> = {};
  for (const [codigo, valorCrudo] of crudos) {
    const n = /^-?[\d.]+(,\d+)?$/.test(valorCrudo) ? parseMontoSii(valorCrudo) : null;
    if (n !== null) codigos[codigo] = n;
    else codigosTexto[codigo] = valorCrudo;
  }
  return {
    at: Number(at),
    vigente: { folio: vigente.folio, fecha: fechaSiiAIso(vigente.fecIng) },
    codigos,
    codigosTexto,
    origen: { servicio: `${F22_APP_URL}#!/f22Completo (Formulario 22)`, descargado: new Date().toISOString() },
  };
}

interface DjDetalleRaw {
  titulo: string;
  dj: number;
  result: {
    codEstado: number;
    estado: string;
    fecha: string | null;
    mes: number | null;
    folio: number;
    medioPresentacion: string | null;
    tipoDeclaracion: string | null;
    casos: number | null;
  }[];
}

// El SII entrega entidades HTML ("Formulario Electr&oacute;nico") en algunos textos.
function decodificarEntidades(s: string): string {
  const mapa: Record<string, string> = {
    aacute: "á", eacute: "é", iacute: "í", oacute: "ó", uacute: "ú", ntilde: "ñ",
    Aacute: "Á", Eacute: "É", Iacute: "Í", Oacute: "Ó", Uacute: "Ú", Ntilde: "Ñ", amp: "&",
  };
  return s.replace(/&(#\d+|\w+);/g, (m, e: string) =>
    e.startsWith("#") ? String.fromCharCode(Number(e.slice(1))) : mapa[e] ?? m
  );
}

// Declaraciones juradas anuales presentadas en un año tributario. Se llama directo al servicio
// JSON de la app (mismas cookies de sesión) en vez de depender de la tabla de años de la pantalla,
// que solo muestra los últimos tres y no siempre se dibuja a tiempo.
async function descargarDDJJEstado(page: Page, rut: string, at: string): Promise<object> {
  await page.goto(DDJJ_CONSULTA_URL, { waitUntil: "load", timeout: PAGE_TIMEOUT_MS });
  await page.waitForNetworkIdle({ idleTime: 2_000, timeout: 20_000 }).catch(() => {});
  const resultado = await page.evaluate(async (rutUrl: string, periodo: string) => {
    const r = await fetch(`/app/djconsulta/${rutUrl}/recurso/v1/dj/getDjIntegralAnualDetalle`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ periodo }),
      credentials: "include",
    });
    return { status: r.status, text: await r.text() };
  }, rut, at);
  if (resultado.status !== 200) {
    throw new Error(`El SII respondió ${resultado.status} al consultar las declaraciones juradas del año ${at}.`);
  }
  let json: { data?: DjDetalleRaw[] };
  try {
    json = JSON.parse(resultado.text) as { data?: DjDetalleRaw[] };
  } catch {
    throw new Error("Respuesta no válida del SII al consultar las declaraciones juradas.");
  }
  const declaraciones = (json.data ?? []).flatMap((dj) =>
    (dj.result ?? []).map((r) => ({
      formulario: dj.dj,
      titulo: decodificarEntidades(dj.titulo.trim()),
      folio: r.folio,
      fecha: r.fecha ? r.fecha.slice(0, 10) : null,
      estado: r.estado,
      codigoEstado: r.codEstado,
      tipo: r.tipoDeclaracion,
      medioPresentacion: r.medioPresentacion ? decodificarEntidades(r.medioPresentacion) : null,
      casos: r.casos,
    }))
  );
  return {
    at: Number(at),
    declaraciones,
    origen: { servicio: "https://www2.sii.cl/djconsulta/estadoddjjs (getDjIntegralAnualDetalle)", descargado: new Date().toISOString() },
  };
}

// ─── Información de terceros (djconsultarentaui) ─────────────────────────────
// Lo que terceros (empleadores, bancos, AFP, sociedades) informaron del contribuyente en sus DDJJ:
// la pantalla "Información para declarar" del SII. Las tablas se devuelven CRUDAS (tabla de
// presentación con celdas colspan/rowspan): la interpretación de columnas queda en el consumidor.
// Implementado según la especificación del documento de requerimientos; con la cuenta de prueba
// (empresa) el servicio responde vacío, así que la forma con datos no está validada aquí.

const TERCEROS_NS = "cl.sii.sdi.lob.renta.djconsultarenta.data.api.interfaces.FacadeService";
const TERCEROS_MAX_PAGINAS = 20;

interface TerceroTablaRaw {
  tabla?: unknown;
  cantRegistros?: number;
  cantidadFilas?: number;
}

interface AgenteRetenedorRaw {
  title?: string;
  listAgenteRetenedor?: Record<string, { resumen?: TerceroTablaRaw; key?: number }>;
}

interface DjDetalleTerceroRaw {
  listDetalle?: { DETALLE?: { detalle?: TerceroTablaRaw } };
}

function callTercerosService<T>(page: Page, method: string, data: Record<string, unknown>): Promise<T> {
  return llamarServicioSii<T>(
    page,
    `/djconsultarentaui/services/data/facadeService/${method}`,
    `${TERCEROS_NS}/${method}`,
    method,
    data
  );
}

async function descargarTerceros(page: Page, rut: string, at: string): Promise<object> {
  await page.goto(`https://www4.sii.cl/djconsultarentaui/internet/#/agenteretenedor/resumen/${at}`, {
    waitUntil: "load",
    timeout: PAGE_TIMEOUT_MS,
  });
  await page.waitForNetworkIdle({ idleTime: 2_000, timeout: 20_000 }).catch(() => {});
  const [num, dv] = rut.split("-");

  const entradas = await callTercerosService<AgenteRetenedorRaw[] | null>(page, "getAgenteRetenedor", { periodo: at });
  const djs: object[] = [];
  for (const entrada of Array.isArray(entradas) ? entradas : []) {
    for (const [dj, info] of Object.entries(entrada.listAgenteRetenedor ?? {})) {
      const resumen = info.resumen;
      const detalle: unknown[] = [];
      let error: string | undefined;
      try {
        const total = resumen?.cantRegistros ?? 0;
        const porPagina = resumen?.cantidadFilas ?? 0;
        const paginas = Math.min(
          TERCEROS_MAX_PAGINAS,
          total > 0 && porPagina > 0 ? Math.ceil(total / porPagina) : 1
        );
        for (let p = 1; p <= paginas; p++) {
          const d = await callTercerosService<DjDetalleTerceroRaw | null>(page, "getDjDetalle", {
            periodo: `${at}00`, rut: num, dv, dj: Number(dj), page: p, key: info.key ?? 0, seccion: "", tipoConsulta: 2,
          });
          const tabla = d?.listDetalle?.DETALLE?.detalle?.tabla;
          if (!tabla) break;
          detalle.push(tabla);
        }
      } catch (err) {
        error = err instanceof Error ? err.message : "Error desconocido";
      }
      djs.push({
        dj: Number(dj),
        titulo: entrada.title ?? null,
        resumen: resumen?.tabla ?? null,
        detalle,
        ...(error ? { error } : {}),
      });
    }
  }
  return {
    at: Number(at),
    djs,
    origen: {
      servicio: "https://www4.sii.cl/djconsultarentaui/internet/ (getAgenteRetenedor, getDjDetalle)",
      descargado: new Date().toISOString(),
    },
  };
}

function rutaPorAnioTributario(
  ruta: string,
  etiqueta: string,
  fn: (page: Page, rut: string, at: string) => Promise<object>
): void {
  app.post(ruta, requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
    const { at } = req.params;
    if (!YEAR_REGEX.test(at)) {
      res.status(400).json({ error: "Año inválido. Use un año de 4 dígitos." });
      return;
    }
    const creds = getRcvCredentialsFromBody(req.body, res);
    if (!creds) return;
    if (!checkRutCooldown(creds.user, res)) return;
    try {
      const data = await withTimeout(
        conSesionSii(etiqueta, creds.user, creds.pass, (page) => fn(page, creds.user, at)),
        REQUEST_TIMEOUT_MS,
        `consulta ${etiqueta}`
      );
      res.json(data);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Error desconocido";
      console.error(`[${ruta}] Error:`, message);
      const status = err instanceof SinDeclaracionError ? 404 : message.includes("inválidas") ? 401 : 500;
      res.status(status).json({ error: message });
    }
  });
}

rutaPorAnioTributario("/api/F22/detalle/:at", "detalle F22", descargarF22Detalle);
rutaPorAnioTributario("/api/F22/estado/:at", "estado F22", descargarF22Estado);
rutaPorAnioTributario("/api/DDJJ/estado/:at", "estado DDJJ", descargarDDJJEstado);
rutaPorAnioTributario("/api/terceros/:at", "información de terceros", descargarTerceros);
rutaPorAnioTributario("/api/boletas/recibidas-anual/:at", "informe anual BHE", (page, _rut, anio) => descargarBHEAnual(page, anio));

app.post("/api/F29/declaracion/:month/:year", requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
  const { month, year } = req.params;
  if (!validateRcvParams(month, year, res)) return;
  const creds = getRcvCredentialsFromBody(req.body, res);
  if (!creds) return;
  if (!checkRutCooldown(creds.user, res)) return;
  try {
    const data = await withTimeout(
      fetchDeclaracionF29(creds.user, creds.pass, month, year),
      REQUEST_TIMEOUT_MS,
      "consulta declaración F29"
    );
    res.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    console.error("[/api/F29/declaracion] Error:", message);
    const status = message.includes("inválidas") ? 401 : 500;
    res.status(status).json({ error: message });
  }
});

app.post("/getEstadoF29", requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
  const { rut, pass } = req.body as { rut?: string; pass?: string };
  if (!rut || !pass) {
    res.status(400).json({ error: "Se requieren los campos 'rut' y 'pass' en el body." });
    return;
  }
  if (!RUT_REGEX.test(rut)) {
    res.status(400).json({ error: "Formato de RUT inválido. Use el formato: 12345678-9" });
    return;
  }
  if (!checkRutCooldown(rut, res)) return;
  try {
    const data = await withTimeout(fetchEstadoF29(rut, pass), REQUEST_TIMEOUT_MS, "consulta Estado F29");
    res.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    console.error("[/getEstadoF29] Error:", message);
    const status = message.includes("inválidas") ? 401 : 500;
    res.status(status).json({ error: message });
  }
});

app.post("/api/RCV/compras/:month/:year", requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
  const { month, year } = req.params;
  if (!validateRcvParams(month, year, res)) return;
  const creds = getRcvCredentialsFromBody(req.body, res);
  if (!creds) return;
  if (!checkRutCooldown(creds.user, res)) return;
  const detallado = !!req.body.Detallado;
  try {
    const data = await withTimeout(
      fetchRCV(month, year, creds.user, creds.pass, "compras", detallado),
      REQUEST_TIMEOUT_MS,
      "consulta RCV compras"
    );
    res.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    console.error("[/api/RCV/compras] Error:", message);
    const status = message.includes("inválidas") ? 401 : 500;
    res.status(status).json({ error: message });
  }
});

app.post("/api/RCV/ventas/:month/:year", requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
  const { month, year } = req.params;
  if (!validateRcvParams(month, year, res)) return;
  const creds = getRcvCredentialsFromBody(req.body, res);
  if (!creds) return;
  if (!checkRutCooldown(creds.user, res)) return;
  const detallado = !!req.body.Detallado;
  try {
    const data = await withTimeout(
      fetchRCV(month, year, creds.user, creds.pass, "ventas", detallado),
      REQUEST_TIMEOUT_MS,
      "consulta RCV ventas"
    );
    res.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    console.error("[/api/RCV/ventas] Error:", message);
    const status = message.includes("inválidas") ? 401 : 500;
    res.status(status).json({ error: message });
  }
});

app.post("/api/boletas/recibidas/:month/:year", requireApiKey, heavyLimiter, async (req: Request, res: Response) => {
  const { month, year } = req.params;
  if (!validateRcvParams(month, year, res)) return;
  const creds = getRcvCredentialsFromBody(req.body, res);
  if (!creds) return;
  if (!checkRutCooldown(creds.user, res)) return;
  try {
    const data = await withTimeout(
      fetchBoletasHonorariosRecibidas(month, year, creds.user, creds.pass),
      REQUEST_TIMEOUT_MS,
      "consulta boletas honorarios recibidas"
    );
    res.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Error desconocido";
    console.error("[/api/boletas/recibidas] Error:", message);
    const status = message.includes("inválidas") ? 401 : 500;
    res.status(status).json({ error: message });
  }
});

// ─── Lotes asíncronos: una sesión SII para varias descargas ──────────────────

type TipoLote =
  | "f29_detalle" | "rcv_compras" | "rcv_ventas" | "bhe_recibidas"
  | "f22_detalle" | "f22_estado" | "ddjj_estado" | "bhe_anual" | "terceros";
const TIPOS_LOTE: readonly TipoLote[] = [
  "f29_detalle", "rcv_compras", "rcv_ventas", "bhe_recibidas",
  "f22_detalle", "f22_estado", "ddjj_estado", "bhe_anual", "terceros",
];
// Tipos anuales: `anio` es el año tributario y no llevan mes.
const TIPOS_LOTE_ANUALES: readonly TipoLote[] = ["f22_detalle", "f22_estado", "ddjj_estado", "bhe_anual", "terceros"];
const LOTE_MAX_ITEMS = 50;
const LOTE_ITEM_TIMEOUT_MS = 180_000;
const LOTE_PAUSA_ENTRE_ITEMS_MS = 2_000;
const LOTE_TTL_MS = 60 * 60_000;
const LOTE_MAX_ALMACENADOS = 100;

interface ItemLote {
  tipo: TipoLote;
  mes?: number;
  anio: number;
  detallado?: boolean;
}

interface ResultadoLote {
  item: ItemLote;
  ok: boolean;
  datos?: object;
  error?: string;
}

interface Lote {
  id: string;
  rut: string;
  estado: "en_cola" | "procesando" | "terminado" | "error";
  total: number;
  hechos: number;
  resultados: ResultadoLote[];
  error?: string;
  terminadoEn?: number;
}

// Solo en memoria: un reinicio o despliegue pierde los lotes. La clave del SII nunca se
// guarda en el lote: vive únicamente en la llamada a ejecutarLote mientras corre.
const lotes = new Map<string, Lote>();
const lotesActivosPorRut = new Set<string>();

function purgarLotesVencidos(): void {
  const ahora = Date.now();
  for (const [id, lote] of lotes) {
    if (lote.terminadoEn !== undefined && ahora - lote.terminadoEn > LOTE_TTL_MS) lotes.delete(id);
  }
}
setInterval(purgarLotesVencidos, 5 * 60_000).unref();

function validarItemsLote(raw: unknown): { items: ItemLote[] } | { error: string } {
  if (!Array.isArray(raw) || raw.length === 0) {
    return { error: "'items' debe ser un arreglo con al menos un ítem." };
  }
  if (raw.length > LOTE_MAX_ITEMS) {
    return { error: `Un lote admite como máximo ${LOTE_MAX_ITEMS} ítems.` };
  }
  const items: ItemLote[] = [];
  for (const [i, entrada] of raw.entries()) {
    const it = (entrada ?? {}) as Record<string, unknown>;
    if (!TIPOS_LOTE.includes(it.tipo as TipoLote)) {
      return { error: `Ítem ${i}: 'tipo' debe ser uno de: ${TIPOS_LOTE.join(", ")}.` };
    }
    const anual = TIPOS_LOTE_ANUALES.includes(it.tipo as TipoLote);
    const mes = Number(it.mes);
    const anio = Number(it.anio);
    if (!anual && (!Number.isInteger(mes) || !MONTH_REGEX.test(String(mes)))) {
      return { error: `Ítem ${i}: 'mes' inválido. Use un valor entre 1 y 12.` };
    }
    if (!Number.isInteger(anio) || !YEAR_REGEX.test(String(anio))) {
      return { error: `Ítem ${i}: 'anio' inválido. Use un año de 4 dígitos.` };
    }
    const item: ItemLote = anual ? { tipo: it.tipo as TipoLote, anio } : { tipo: it.tipo as TipoLote, mes, anio };
    if (it.tipo === "rcv_compras" || it.tipo === "rcv_ventas") item.detallado = it.detallado === true;
    items.push(item);
  }
  return { items };
}

function descargarItemLote(page: Page, rut: string, item: ItemLote): Promise<object> {
  const mes = String(item.mes ?? "");
  const anio = String(item.anio);
  switch (item.tipo) {
    case "f29_detalle":
      return descargarF29Detalle(page, rut, mes, anio);
    case "rcv_compras":
      return descargarRCV(page, mes, anio, rut, "compras", item.detallado === true);
    case "rcv_ventas":
      return descargarRCV(page, mes, anio, rut, "ventas", item.detallado === true);
    case "bhe_recibidas":
      return descargarBHE(page, mes, anio);
    case "f22_detalle":
      return descargarF22Detalle(page, rut, anio);
    case "f22_estado":
      return descargarF22Estado(page, rut, anio);
    case "ddjj_estado":
      return descargarDDJJEstado(page, rut, anio);
    case "bhe_anual":
      return descargarBHEAnual(page, anio);
    case "terceros":
      return descargarTerceros(page, rut, anio);
  }
}

// Tras un timeout la página puede quedar a medio navegar: seguir usándola daría
// resultados de otra consulta, así que el lote se detiene.
function esTimeout(err: unknown): boolean {
  const message = err instanceof Error ? err.message : "";
  return (
    (err instanceof Error && err.name === "TimeoutError") ||
    /^Tiempo máximo excedido|^Timeout esperando|^Waiting failed|^Navigation timeout/.test(message)
  );
}

async function ejecutarLote(lote: Lote, pass: string, items: ItemLote[]): Promise<void> {
  const noEjecutados = (desde: number, motivo: string) => {
    for (const item of items.slice(desde)) lote.resultados.push({ item, ok: false, error: motivo });
  };
  try {
    await conSesionSii("lote", lote.rut, pass, async (page) => {
      lote.estado = "procesando";
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        try {
          const datos = await withTimeout(
            descargarItemLote(page, lote.rut, item),
            LOTE_ITEM_TIMEOUT_MS,
            `ítem ${i + 1} (${item.tipo})`
          );
          lote.resultados.push({ item, ok: true, datos });
        } catch (err) {
          const message = err instanceof Error ? err.message : "Error desconocido";
          console.error(`[lote ${lote.id}] ítem ${i + 1} (${item.tipo}) falló: ${message}`);
          lote.resultados.push({ item, ok: false, error: message });
          if (esTimeout(err)) {
            lote.error = "Lote detenido por un timeout: la sesión quedó en un estado incierto.";
            lote.hechos = i + 1;
            noEjecutados(i + 1, "No ejecutado: el lote se detuvo por un timeout previo.");
            return;
          }
        }
        lote.hechos = i + 1;
        if (i < items.length - 1) await new Promise((r) => setTimeout(r, LOTE_PAUSA_ENTRE_ITEMS_MS));
      }
    });
    lote.estado = lote.error ? "error" : "terminado";
  } catch (err) {
    // Login fallido o Chromium sin arrancar: ningún ítem llegó a ejecutarse.
    lote.error = err instanceof Error ? err.message : "Error desconocido";
    lote.estado = "error";
    noEjecutados(lote.resultados.length, "No ejecutado: no se pudo abrir la sesión en el SII.");
    console.error(`[lote ${lote.id}] error de sesión: ${lote.error}`);
  } finally {
    lote.terminadoEn = Date.now();
    lotesActivosPorRut.delete(lote.rut);
    console.log(`[lote ${lote.id}] ${lote.estado}: ${lote.hechos}/${lote.total} ítems`);
  }
}

const lotePollLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Demasiadas consultas de lote. Espere un momento antes de intentarlo de nuevo." },
});

app.post("/api/v1/lotes", requireApiKey, heavyLimiter, (req: Request, res: Response) => {
  const creds = getRcvCredentialsFromBody(req.body, res);
  if (!creds) return;
  const validacion = validarItemsLote((req.body as { items?: unknown }).items);
  if ("error" in validacion) {
    res.status(400).json({ error: validacion.error });
    return;
  }
  if (!checkRutCooldown(creds.user, res)) return;
  purgarLotesVencidos();
  if (lotes.size >= LOTE_MAX_ALMACENADOS) {
    res.status(503).json({ error: "Demasiados lotes almacenados. Reintente en unos minutos." });
    return;
  }

  const lote: Lote = {
    id: randomUUID(),
    rut: creds.user,
    estado: "en_cola",
    total: validacion.items.length,
    hechos: 0,
    resultados: [],
  };
  lotes.set(lote.id, lote);
  lotesActivosPorRut.add(lote.rut);
  void ejecutarLote(lote, creds.pass, validacion.items);

  res.status(202).json({
    id: lote.id,
    estado: lote.estado,
    total: lote.total,
    consultar: `/api/v1/lotes/${lote.id}`,
  });
});

app.get("/api/v1/lotes/:id", requireApiKey, lotePollLimiter, (req: Request, res: Response) => {
  const lote = lotes.get(req.params.id);
  if (!lote) {
    res.status(404).json({ error: "Lote no encontrado o vencido." });
    return;
  }
  res.json({
    id: lote.id,
    estado: lote.estado,
    total: lote.total,
    hechos: lote.hechos,
    resultados: lote.resultados,
    ...(lote.error ? { error: lote.error } : {}),
  });
});

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[global] Unhandled Express error:", err.message);
  res.status(500).json({ error: "Error interno del servidor" });
});

app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});
