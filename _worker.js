const decryptAES = async (data, key, iv) => {
  const decoder = new TextDecoder('utf-8');
  const encoder = new TextEncoder();
  const keyBuffer = encoder.encode(key);
  const ivBuffer = encoder.encode(iv);
  const dataBuffer = hexToUint8Array(data);
  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-CBC' }, false, ['decrypt']);
  const decryptedData = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBuffer }, cryptoKey, dataBuffer);
  return decoder.decode(decryptedData);
};
const hexToUint8Array = (hex) => {
  const view = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return view;
};
const fetchKeyAndIv = async () => {
  const response = await fetch('https://key.enkelte.ggff.net/');
  const json = await response.json();
  return { key: atob(json.key), iv: atob(json.iv) };
};
const formatVlessLink = ({ protocol, uuid, address, port, encryption, security, sni, fingerprint, path, type, packetEncoding, host, hostname }) => 
  `${protocol}://${uuid}@${address}:${port}?security=${security}&sni=${sni}&fp=${fingerprint}&type=${type}&path=${path}&host=${host}&packetEncoding=${packetEncoding}&encryption=${encryption}#${hostname}`;
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
const handleRequest = async (request) => {
  try {
    const { key, iv } = await fetchKeyAndIv();
    const response = await fetch('https://vless.enkelte.ggff.net/vless_list');
    const encryptedData = await response.text();
    const decodedData = atob(encryptedData);
    const decryptedJson = await decryptAES(decodedData, key, iv);
    const resultData = JSON.parse(decryptedJson);
    const vlessLinks = resultData.data.map(formatVlessLink);
    const resultString = vlessLinks.join('\n');
    const base64Encoded = uint8ArrayToBase64(new TextEncoder().encode(resultString));
    return new Response(base64Encoded, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  } catch (error) {
    console.error('Error in main process:', error);
    return new Response('Error processing request', { status: 500 });
  }
};
const uint8ArrayToBase64 = (uint8Array) => btoa(String.fromCharCode(...uint8Array));