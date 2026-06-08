import puppeteer, { executablePath } from "puppeteer";
import path from "path";
import fs from 'node:fs';

const browser = await puppeteer.launch({
  //headless: "shell",
  headless: false,
  //executablePath: executablePath(),
  /*args: [
    "--disable-setuid-sandbox",
    "--no-sandbox",
    "--disable-gpu",
    "--no-first-run",
  ],*/
  userDataDir: "/tmp/myChromeSession",
});
const page = await browser.newPage();

// Navigate the page to a URL.
await page.goto(
  "https://zeusr.sii.cl//AUT2000/InicioAutenticacion/IngresoRutClave.html?https://misiir.sii.cl/cgi_misii/siihome.cgi"
);

// Type into search box.

await page.locator("#rutcntr").fill("76284413-3"); //"76284413-3"
await page.locator("#clave").fill("CONTADOR7"); //
await page.click("#bt_ingresar");
await page.waitForNavigation(),
  await page.goto("https://www4.sii.cl/consdcvinternetui/#/index", {
    waitUntil: "load",
    timeout: 0,
  });
await (new Promise((resolve,reject)=>setTimeout(resolve,4000)))
await page.waitForSelector("#periodoMes");
await page.locator("#periodoMes").fill('02');
await page.waitForSelector("#my-wrapper > div.web-sii.cuerpo > div.container > div:nth-child(1) > div > div.ng-scope > div > div.panel.panel-primary > div > form > div:nth-child(2) > select:nth-child(3)");
await page.locator("#my-wrapper > div.web-sii.cuerpo > div.container > div:nth-child(1) > div > div.ng-scope > div > div.panel.panel-primary > div > form > div:nth-child(2) > select:nth-child(3)").fill('2023');
await page.locator("#my-wrapper > div.web-sii.cuerpo > div.container > div:nth-child(1) > div > div.ng-scope > div > div.panel.panel-primary > div > form > div:nth-child(3) > button").click();

await (new Promise((resolve,reject)=>setTimeout(resolve,4000)))
await page.waitForSelector("#my-wrapper > div.web-sii.cuerpo > div.container > div:nth-child(2) > div > div:nth-child(3) > div:nth-child(4) > div:nth-child(1) > div:nth-child(5) > button");
await page.locator("#my-wrapper > div.web-sii.cuerpo > div.container > div:nth-child(2) > div > div:nth-child(3) > div:nth-child(4) > div:nth-child(1) > div:nth-child(5) > button").click();

/*
const downloadPath = path.resolve('./download');
console.log(downloadPath)
const client = await page.target().createCDPSession();
let guids = {};
await client.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: downloadPath,
    eventsEnabled: true
});

client.on('Browser.downloadWillBegin', async (event) => {
    //some logic here to determine the filename
    //the event provides event.suggestedFilename and event.url
    guids[event.guid] = event.suggestedFilename;
});

client.on('Browser.downloadProgress', async (event) => {
    // when the file has been downloaded, locate the file by guid and rename it
    if(event.state === 'completed') {
        fs.renameSync(path.resolve(downloadPath, guids[event.guid]), path.resolve(downloadPath, "data.csv"));
        fs.readFile('./download/data.csv', 'utf8', (err, data) => {
            if (err) {
              console.error(err);
              return;
            }
            var lines = data.split("\n");
            var fields = lines[0].split(';');
            lines.shift();
            if(lines[lines.length-1]=="") lines.pop();
            var registros = [];
            for(var line of lines){
                let registro = {};
                var values = line.split(";")
                for(var i in fields){
                    registro[fields[i]] = values[i]
                }
                registros.push(registro)
            }
            console.log(registros)
          });
        //browser.close();
    }
});

await (new Promise((resolve,reject)=>setTimeout(resolve,4000)))
await page.waitForSelector("#pendiente > div:nth-child(4) > div:nth-child(1) > div:nth-child(5) > button");
await page.locator("#pendiente > div:nth-child(4) > div:nth-child(1) > div:nth-child(5) > button").click();
*/

