import express, { Express, NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import puppeteer, { Browser, executablePath, Page } from "puppeteer";
import { parse } from "node-html-parser";
import path from "path";
import os from "node:os";
import fs from "node:fs";
import { randomUUID, timingSafeEqual } from "node:crypto";
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
  const operacion   = mode === "compras" ? "COMPRA" : "VENTA";
  const ptributario = year + month.padStart(2, "0");
  const rutNum      = user.split("-")[0];
  const dv          = user.split("-")[1];

  await sessionSemaphore.acquire();
  const sessionId  = randomUUID();
  const browser    = await launchBrowser(sessionId);
  let pageRef: Page | null = null;

  try {
    const page = await browser.newPage();
    pageRef = page;

    // Todos los acumuladores se llenan via page.on("response") antes de cualquier navegación
    // para evitar race conditions donde la respuesta llega antes de registrar waitForResponse.
    const resumenResponses: Record<string, unknown>[] = [];
    let empresasAutorizadasReceived = false;
    let detalleRaw: Record<string, unknown> | null = null;
    let detalleStatus = 0;

    page.on("response", async (r) => {
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
            console.log(`[net] getDetalle recibido, keys: ${Object.keys(data)}, snippet: ${JSON.stringify(data).slice(0, 200)}`);
          } catch (e) {
            console.warn("[net] getDetalle no-JSON:", (e as Error).message);
          }
        }
      }
    });

    // 1. Login
    await login(page, user, pass);

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
    // Ignorar errores al cerrar: el portal SII puede tener navegaciones Angular pendientes
    // que generan "Navigation timeout" al cerrar el browser, matando el return exitoso.
    if (pageRef) await logout(pageRef);
    await closeBrowserSafely(browser, "cierre navegador RCV");
    cleanupSession(sessionId);
    sessionSemaphore.release();
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
  await sessionSemaphore.acquire();
  const sessionId = randomUUID();
  const browser = await launchBrowser(sessionId);
  let pageRef: Page | null = null;

  try {
    const page = await browser.newPage();
    pageRef = page;

    await login(page, user, pass);

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
  } finally {
    if (pageRef) await logout(pageRef);
    await closeBrowserSafely(browser, "cierre navegador boletas honorarios");
    cleanupSession(sessionId);
    sessionSemaphore.release();
  }
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
  await sessionSemaphore.acquire();
  const sessionId = randomUUID();
  const browser = await launchBrowser(sessionId);
  let pageRef: Page | null = null;
  try {
    const page = await browser.newPage();
    pageRef = page;
    await login(page, rut, pass);
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
  } finally {
    if (pageRef) await logout(pageRef);
    await closeBrowserSafely(browser, "cierre navegador F29");
    cleanupSession(sessionId);
    sessionSemaphore.release();
  }
}

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
