const config = {
  WebToken: 'B4C8FE1C-90F3-F4FE-FE64-7FB011BDD5DF',//此处修改登录密码token
  FileName: 'Vless',MainData: '',urls: [],subconverter: "SUBAPI.CMLiussss.net",subconfig: "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini", subProtocol: 'https',
};
export default {
  async fetch(request, env) {
      const userAgent = request.headers.get('User-Agent')?.toLowerCase() || "null";
      const url = new URL(request.url);
      const token = url.searchParams.get('token');
      config.WebToken = env.TOKEN || config.WebToken;
      config.subconverter = env.SUBAPI || config.subconverter;
      config.subconfig = env.SUBCONFIG || config.subconfig;
      config.FileName = env.SUBNAME || config.FileName;
      config.MainData = env.LINK || config.MainData;
      if (env.LINKSUB) config.urls = await addLinks(env.LINKSUB);
      await fetchAndDecryptData();
      const currentDate = new Date();
      currentDate.setHours(0, 0, 0, 0);
      const fakeToken = await MD5MD5(`${config.WebToken}${Math.ceil(currentDate.getTime() / 1000)}`);
      let allLinks = await addLinks(config.MainData + '\n' + config.urls.join('\n'));
      let selfHostedNodes = "", subscriptionLinks = "";
      allLinks.forEach(x => x.toLowerCase().startsWith('http') ? subscriptionLinks += x + '\n' : selfHostedNodes += x + '\n');
      config.MainData = selfHostedNodes;
      config.urls = await addLinks(subscriptionLinks);
      if (![config.WebToken, fakeToken].includes(token) && !url.pathname.includes("/" + config.WebToken)) {
          return new Response(await forbiddenPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
      }
      const subscriptionFormat = determineSubscriptionFormat(userAgent, url);
      let subscriptionConversionUrl = `${url.origin}/${await MD5MD5(fakeToken)}?token=${fakeToken}`;
      let req_data = config.MainData + (await getSubscription(config.urls, "v2rayn", request.headers.get('User-Agent')))[0].join('\n');
      subscriptionConversionUrl += `|${(await getSubscription(config.urls, "v2rayn", request.headers.get('User-Agent')))[1]}`;
      if (env.WARP) subscriptionConversionUrl += `|${(await addLinks(env.WARP)).join("|")}`;
      const base64Data = btoa(req_data);
      if (subscriptionFormat === 'base64' || token === fakeToken) {
          return new Response(base64Data, { headers: { "content-type": "text/plain; charset=utf-8" } });
      }
      try {
          const subconverterResponse = await fetch(buildSubconverterUrl(subscriptionFormat, subscriptionConversionUrl));
          if (!subconverterResponse.ok) throw new Error();
          let subconverterContent = await subconverterResponse.text();
          if (subscriptionFormat === 'clash') subconverterContent = await clashFix(subconverterContent);
          return new Response(subconverterContent, {
              headers: {
                  "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(config.FileName)}; filename=${config.FileName}`,
                  "content-type": "text/plain; charset=utf-8",
              },
          });
      } catch {
          return new Response(base64Data, { headers: { "content-type": "text/plain; charset=utf-8" } });
      }
  }
};
function formatVlessLink({ protocol = '', uuid = '', address = '', port = '', encryption = '', security = '', sni = '', fingerprint = '', path = '', type = '', publicKey = '', shortId = '', flow = '', hostname = '', additionalParams: { host = '' } = {}}) {
  return `${protocol}://${uuid}@${address}:${port}?security=${security}&sni=${sni}&fp=${fingerprint}&type=${type}&path=${path}&host=${host}&pbk=${publicKey}&sid=${shortId}&flow=${flow}&encryption=${encryption}#${encodeURIComponent(hostname)}`;
}
async function fetchAndDecryptData() {
  const apiUrl = 'https://vless.enkelte.ggff.net/vless_list';
  const keyApiUrl = 'https://key.enkelte.ggff.net/';
  try {
    const { key, iv } = await (await fetch(keyApiUrl)).json();
    const decodedKey = atob(key);
    const decodedIv = atob(iv);
    const encryptedData = await (await fetch(apiUrl)).text();
    const decryptedJson = await decryptAES(atob(encryptedData), decodedKey, decodedIv);
    const data = JSON.parse(decryptedJson).data;
    config.MainData = data.map(formatVlessLink).join('\n');
  } catch (error) {
    throw new Error('Error fetching or decrypting data: ' + error.message);
  }
}
async function decryptAES(data, key, iv) {
  const decoder = new TextDecoder('utf-8');
  const encoder = new TextEncoder();
  const keyBuffer = encoder.encode(key);
  const ivBuffer = encoder.encode(iv);
  const dataBuffer = hexToUint8Array(data);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-CBC' }, false, ['decrypt']);
  const decryptedData = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBuffer }, cryptoKey, dataBuffer);
  return decoder.decode(decryptedData);
}
function hexToUint8Array(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
function determineSubscriptionFormat(userAgent, url) {
  if (userAgent.includes('null') || userAgent.includes('subconverter')) return 'base64';
  if (userAgent.includes('clash') || url.searchParams.has('clash')) return 'clash';
  if (userAgent.includes('sing-box') || url.searchParams.has('sb') || url.searchParams.has('singbox')) return 'singbox';
  if (userAgent.includes('surge') || url.searchParams.has('surge')) return 'surge';
  return 'base64';
}
function buildSubconverterUrl(subscriptionFormat, subscriptionConversionUrl) {
  return `${config.subProtocol}://${config.subconverter}/sub?target=${subscriptionFormat}&url=${encodeURIComponent(subscriptionConversionUrl)}&config=${encodeURIComponent(config.subconfig)}`;
}
async function addLinks(data) {
  return data.split("\n").filter(e => e.trim() !== "");
}
async function getSubscription(urls, UA, userAgentHeader) {
  const headers = { "User-Agent": userAgentHeader || UA };
  let subscriptionContent = [], unconvertedLinks = [];
  for (const url of urls) {
      try {
          const response = await fetch(url, { headers });
          if (response.status === 200) {
              subscriptionContent.push((await response.text()).split("\n"));
          } else {
              unconvertedLinks.push(url);
          }
      } catch {
          unconvertedLinks.push(url);
      }
  }
  return [subscriptionContent.flat(), unconvertedLinks];
}
async function clashFix(content) {
  return content.split("\n").reduce((acc, line) => {
      if (line.startsWith("  - name: ")) acc += `  - name: ${line.split("name: ")[1]}\n`;
      else acc += line + "\n";
      return acc;
  }, '');
}
async function forbiddenPage() {
  return `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Access Denied</p></body></html>`;
}
async function MD5MD5(value) {
  const encoded = new TextEncoder().encode(value);
  const buffer = await crypto.subtle.digest("MD5", await crypto.subtle.digest("MD5", encoded));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function aes128cbcDecrypt(encryptedText, key, iv) {
  const encryptedBuffer = hexStringToUint8Array(encryptedText);
  const algorithm = { name: 'AES-CBC', iv };
  const keyObj = await crypto.subtle.importKey('raw', key, algorithm, false, ['decrypt']);
  try {
      const decryptedBuffer = await crypto.subtle.decrypt(algorithm, keyObj, encryptedBuffer);
      return new TextDecoder().decode(decryptedBuffer).replace(/\0+$/, '');
  } catch {
      throw new Error('Decryption failed');
  }
}
function hexStringToUint8Array(hexString) {
  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}
