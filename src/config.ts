import { ensureTrailingSlash } from "./utils";
import { signDerCertficate } from "./const/cert";
import { setDeviceState } from "./state";

declare const __BACKEND_URL__: string;
declare const __NODE_ENV__: string;
declare const __DEVICE_PATH__: string;

export const config = {
  backendUrl: ensureTrailingSlash(__BACKEND_URL__),
  nodeEnv: __NODE_ENV__,
  isDev: __NODE_ENV__ === 'development',
  devicePath: ensureTrailingSlash(__DEVICE_PATH__),
  signDerCertficate: signDerCertficate,
  getProxy(): ProxyConfig {
    return {...proxyConfig};
  }
} as const;

interface ProxyConfig {
  address: string | null;
  port: number | null;
  caCertificate: string | null;
}

const proxyConfig: ProxyConfig  = {
  address: null,
  port: null,
  caCertificate: null
};

export function loadConfigFromStorage(): void {
  try {
    const stored = localStorage.getItem('unpinner_config');
    if (stored) {
      const parsed = JSON.parse(stored);
      Object.assign(proxyConfig, parsed);
      setDeviceState({isProxyConfigured: true});

    }
  } catch (error) {
    console.warn('Failed to load config from storage ', error);
  }
}

export function updateProxyConfig(
  address: string | null,
  port: number | null,
  certificate: string | null
): void {
  if (proxyConfig.address) {
    proxyConfig.address = address;
  }
  if (proxyConfig.port) {
    proxyConfig.port = port;
  }
  if (proxyConfig.caCertificate) {
    proxyConfig.caCertificate = certificate
  }

  localStorage.setItem('unpinner_config', JSON.stringify(proxyConfig));
}


export function generateFridaConfigJs(proxy: ProxyConfig): string {
  const certPem = proxy.caCertificate || '';
  const host = proxy.address || '127.0.0.1';
  const port = proxy.port || '8080';

  return `// Automatically generated proxy configuration for Frida scripts
const CERT_PEM = \`${certPem}\`;
const PROXY_HOST = '${host}';
const PROXY_PORT = ${port};
const DEBUG_MODE = false;
`;
}


