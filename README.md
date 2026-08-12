# Inlock

Inlock é um firewall de aplicação e reverse proxy para serviços locais e
containers Docker. Cada projeto recebe uma rota protegida e uma cadeia de
políticas avaliada antes de qualquer requisição chegar ao upstream.

O painel é renderizado com [PyReact](https://github.com/wanbnn/pyreact), usa
[UIKitPR](https://github.com/wanbnn/uikitpr), ícones nativos do
[6cons](https://github.com/wanbnn/6cons) e dependências reproduzíveis pelo
[PRPM](https://github.com/wanbnn/prpm). O Leaflet 1.9.4 está versionado em
`inlock/static/vendor`, portanto nenhum JavaScript ou CSS do mapa depende de CDN.

## Instalação rápida — Debian/Ubuntu

```bash
curl -fsSL https://raw.githubusercontent.com/wanbnn/ntslock/main/install.sh | sudo bash
```

O instalador requer Python 3.11+, cria um usuário de sistema, ambiente virtual,
segredos, diretório de dados e serviço `systemd`. Ao terminar, ele exibe o token
administrativo. Abra `http://IP-DO-SERVIDOR:14900` e informe esse token no painel.

## O que já funciona

- descoberta automática de containers, imagens, estados e portas pelo Docker;
- tomada transparente das portas publicadas com `INLOCK_REDIRECT` e bloqueio
  defensivo na cadeia `DOCKER-USER`;
- projetos por host (`app.exemplo.com`) ou rota (`/p/<slug>`);
- reverse proxy HTTP com preservação dos cabeçalhos de encaminhamento;
- rate limit por IP ou global com janela deslizante;
- whitelist e blacklist com IPv4, IPv6 e CIDR;
- bloqueio de user-agent com padrões glob (`*bot*`, `curl/*`);
- bot score local de 0 a 100 com threshold configurável e desafio visual;
- limites por país, estado, cidade ou raio desenhado no Leaflet;
- auditoria de decisões e eventos no SQLite;
- desafio por QR Code renovado automaticamente a cada 60 segundos;
- token QR opaco, aleatório e de uso único, sem segredo no cliente;
- aprovação vinculada ao navegador que exibiu o QR e sessão em cookie
  `HttpOnly` assinado.
- modo totem, no qual o QR abre a aplicação somente no dispositivo móvel e a
  tela original permanece exibindo códigos rotativos.

## Como o QR Code evita o acesso direto

```text
navegador          Inlock                    celular
    | POST challenge  |                          |
    |<-- QR opaco ----|                          |
    |                 |<-- lê e confirma token --|
    | poll (vinculado)|                          |
    |<-- cookie HTTPOnly assinado                |
    |-------- requisição liberada ao upstream -->|
```

O QR não carrega permissões decodificáveis: contém somente 256 bits aleatórios.
O servidor armazena o hash desse valor, expira o desafio em 60 segundos,
invalida o QR anterior na rotação e libera apenas o navegador que iniciou o
desafio. Copiar uma URL direta do upstream não funciona quando a aplicação está
exposta somente pela rede Docker e o Inlock é seu único ponto de entrada.

Ao selecionar um container, o Inlock também gerencia sua exposição no host. As
portas Docker publicadas continuam disponíveis localmente para o proxy, mas
conexões TCP externas são desviadas para o gateway pela cadeia
`INLOCK_REDIRECT`. Assim, a URL e a porta originais passam a exibir o QR Code;
depois da aprovação, o Inlock encaminha a requisição ao container. A cadeia
`INLOCK_GUARD` bloqueia tráfego que não puder ser interceptado. Se o Docker ou o
firewall não puderem ser gerenciados, o cadastro é recusado: o sistema não
apresenta uma proteção falsa. O estado e as portas são reconciliados novamente
a cada 10 segundos para acompanhar reinícios e mudanças nos containers.

Nenhum QR Code pode provar presença física absoluta: uma transmissão ao vivo ou
foto do código ainda pode ser lida remotamente dentro dos 60 segundos. Para
ambientes de alto risco, combine esta confirmação de presença com login, WebAuthn
ou aprovação em um dispositivo previamente registrado.

### Modos do QR Code

- **Modo padrão:** o celular confirma o desafio e o navegador que mostrou o QR
  é liberado.
- **Modo totem:** a leitura consome o token, cria a sessão no celular e abre
  nele a mesma rota solicitada. O navegador do totem nunca recebe a sessão;
  depois da leitura ele gera um novo QR para a próxima pessoa.

O switch **Modo totem** fica nas configurações do projeto e, quando ativado,
mantém automaticamente a exigência de QR Code ligada.

## Bot score e verificação humana

A política **Bot score** calcula uma probabilidade local de automação de 0
(aparência humana) a 100 (forte suspeita). Uma primeira análise considera
user-agent, cabeçalhos de navegação, continuidade e integridade dos cookies,
reputação local do IP e mudanças de fingerprint. Um navegador novo que não
atingiu o threshold recebe um desafio progressivo curto antes da aplicação.

Esse primeiro estágio executa JavaScript e exige uma confirmação humana depois
de um pequeno intervalo. Ele mede webdriver e globals de automação, tempo até o
clique, evento confiável, movimentos de ponteiro, cookies, storage, idiomas,
plugins, características da tela e visibilidade da página. A prova resultante é
assinada, expira em 30 minutos e fica vinculada ao navegador, ao projeto e ao
fingerprint da requisição. JavaScript ausente, interação instantânea, prova
adulterada ou mudança incompatível elevam o score.

Depois da prova, o gateway continua observando somente navegações de documento
de nível superior: intervalos impossivelmente curtos, rajadas de páginas e
enumeração rápida de muitos caminhos aumentam o score. Assets paralelos de uma
página (`script`, CSS e imagens) não entram nessa contagem.

A reputação do IP é construída sem serviços externos a partir dos últimos 15
minutos de desafios, falhas e bloqueios observados pelo próprio Inlock. Isso
evita enviar endereços de visitantes a terceiros, mas não equivale a uma base
global de abuso e deve ser calibrado com atenção em redes NAT compartilhadas.

Quando o TLS termina diretamente no Inlock, o servidor usa versão e cipher
disponíveis na conexão. Atrás do Cloudflare, o TLS do visitante termina na borda
e esses dados não chegam ao origin. Um proxy confiável pode sobrescrever um
header com JA3/JA4 e o Inlock o consumirá ao configurar, por exemplo:

```env
INLOCK_TLS_FINGERPRINT_HEADER=X-Inlock-JA4
```

Não habilite um header que o proxy apenas repassa: ele precisa remover qualquer
valor enviado pelo cliente e gravar o fingerprint verdadeiro. O header só é
aceito quando a conexão vem de uma rede em `INLOCK_TRUSTED_PROXIES`.

Se o score final atingir o threshold, o visitante seleciona formas e cores em
uma grade gerada localmente. O desafio
expira, permite no máximo três tentativas, é vinculado ao navegador e sua resposta
é validada no servidor. Ao acertar, recebe uma sessão `HttpOnly` assinada de 30
minutos e volta à URL original; as demais políticas e o QR Code continuam sendo
avaliados normalmente. Nenhum provedor externo de CAPTCHA é utilizado.

Bot score heurístico não é uma prova de identidade e cabeçalhos podem ser
imitados. Use-o como uma camada contra automação oportunista, combinado com rate
limit, listas de IP e autenticação da aplicação.

## Executar em desenvolvimento

Requer Python 3.11+ e PRPM:

```bash
python -m pip install prpm
prpm install
cp .env.example .env
prpm run dev
```

Abra `http://localhost:14900`. Sem `INLOCK_ADMIN_TOKEN`, a API administrativa
aceita somente conexões loopback. Para acesso remoto, o token é obrigatório; o
painel o solicita uma vez e o mantém no armazenamento local do navegador.

Os comandos úteis são:

```bash
prpm run test
prpm run lint
prpm run serve
```

## Instalar com Docker Compose

Gere segredos e informe o GID do socket Docker:

```bash
cp .env.example .env
printf '\nDOCKER_GID=%s\n' "$(stat -c '%g' /var/run/docker.sock)" >> .env
docker compose up -d --build
```

Adicione ao serviço `inlock` caso o host exija associação explícita ao grupo:

```yaml
group_add:
  - "${DOCKER_GID}"
```

O socket Docker concede poder equivalente a root mesmo montado como somente
leitura. O Inlock usa apenas `ping` e listagem/inspeção de containers, mas em uma
instalação endurecida prefira um proxy de socket que permita exclusivamente
`/_ping`, `/containers/json` e `/containers/*/json`.

O Compose usa a rede do host e concede somente `CAP_NET_ADMIN` para que o
Inlock alcance as portas locais dos containers e mantenha sua cadeia de
firewall. Confira o isolamento ativo com:

```bash
sudo iptables -S INLOCK_GUARD
sudo iptables -t nat -S INLOCK_REDIRECT
sudo iptables -t nat -S INLOCK_OUTPUT
```

### Cloudflare Tunnel

O Inlock também intercepta conexões de origem feitas pelo próprio host, como um
serviço `cloudflared`, através de `INLOCK_OUTPUT`. O usuário do processo Inlock
é excluído dessa regra para que o proxy consiga alcançar o upstream sem entrar
em loop.

A configuração recomendada é apontar o túnel diretamente para o gateway e
cadastrar `journey.hephestos.com.br` como **Host público** do projeto:

```yaml
ingress:
  - hostname: journey.hephestos.com.br
    service: http://127.0.0.1:14900
    originRequest:
      httpHostHeader: journey.hephestos.com.br
  - service: http_status:404
```

Usar a porta publicada original também é interceptado quando o `cloudflared`
roda como serviço do host. Se ele roda em outro container e usa diretamente o
nome ou IP privado do container protegido, esse caminho não atravessa o host;
nesse caso a rota do túnel deve obrigatoriamente usar `127.0.0.1:14900` (com
rede do host) ou outro endereço que alcance a porta `14900` do Inlock.

## Publicar uma aplicação

1. No painel, abra **Containers** e escolha **Proteger container**.
2. Confirme a URL upstream descoberta. Portas publicadas usam
   `127.0.0.1:porta`; serviços sem publicação usam o IP privado da rede Docker.
3. Defina um host público, por exemplo `app.exemplo.com`, ou use `/p/meu-app`.
4. Ative o QR Code e adicione as políticas necessárias.
5. Aponte seu proxy TLS (Caddy, Traefik ou Nginx) para o Inlock, nunca diretamente
   para o container protegido.

No momento do cadastro, o Inlock inspeciona todas as portas do container e
assume os bindings TCP públicos no firewall do host. Abrir a URL original do
container mostra o QR Code, e não a aplicação. O upstream não é modificado nem
recebe código injetado; o controle ocorre no ponto correto da rede Docker,
impedindo o bypass mesmo que alguém descubra a porta publicada.

Exemplo Caddy:

```caddyfile
inlock.exemplo.com, app.exemplo.com {
    reverse_proxy 127.0.0.1:14900
}
```

Configure `INLOCK_ADMIN_HOST=inlock.exemplo.com` e cadastre
`app.exemplo.com` como host público do projeto. As rotas `/static`, `/api/gate`
e `/gate` são reservadas pelo Inlock em hosts protegidos.

## Geolocalização e mapa self-hosted

A avaliação geográfica usa uma base MMDB local compatível com GeoIP2:

```env
INLOCK_GEOIP_CITY_DB=/data/GeoLite2-City.mmdb
```

Sem a base, políticas geográficas negam por padrão (`on_unknown=deny`). O painel
permite optar conscientemente por liberar localização desconhecida. Leaflet é
servido localmente; os tiles usam OpenStreetMap por padrão. Para operação
totalmente local, publique seus próprios tiles e ajuste:

```env
INLOCK_TILE_URL=https://tiles.seudominio/{z}/{x}/{y}.png
```

A área **Relatórios** usa Apache ECharts e o GeoJSON mundial servidos pelo
próprio Inlock, sem CDN. Para posicionar corretamente o destino no mapa de
fluxos, configure a localização do servidor:

```env
INLOCK_SERVER_LATITUDE=-9.6658
INLOCK_SERVER_LONGITUDE=-35.7353
INLOCK_SERVER_LOCATION_NAME=Servidor Inlock
```

O mapa de origens depende da mesma base GeoIP2 local. Logs coletados antes da
ativação dessa base continuam disponíveis, mas aparecem sem coordenadas.

Para navegadores, o Inlock solicita consentimento de localização na tela do QR
Code e, em projetos sem QR, antes do primeiro encaminhamento ao upstream. No
modo totem, a solicitação também acontece no celular que abrirá a aplicação.
A posição consentida é vinculada ao projeto por um cookie opaco HttpOnly durante
8 horas (`INLOCK_LOCATION_TTL_SECONDS`) e prevalece sobre a estimativa GeoIP.
Se o usuário recusar, o acesso continua com rastreabilidade por IP. A API de
geolocalização dos navegadores exige HTTPS ou localhost.

## Notas de produção

### Login proprietário espelhado

A política **Login proprietário** espelha uma página de autenticação autorizada
antes de liberar o upstream do projeto. Redirects entre diferentes origens são
acompanhados dentro da URL do Inlock; links e recursos descobertos em páginas já
autorizadas também são espelhados. Uma origem arbitrária inserida diretamente no
endpoint continua bloqueada até ser descoberta nessa cadeia.

O switch **Forçar modo computador** altera somente o login espelhado: o Inlock
envia um User-Agent desktop e fixa o viewport das páginas de autenticação em
1280 pixels. Depois da liberação, o upstream protegido continua recebendo as
características reais do dispositivo e permanece responsivo em celulares.

Os cookies da aplicação de login permanecem somente na memória do Inlock e são
associados a uma sessão efêmera do navegador; não são enviados ao cliente nem
gravados no banco. Corpos de formulários são retransmitidos em memória e não
entram nos logs de auditoria. A sessão expira em 15 minutos por padrão:

```env
INLOCK_PROPRIETARY_LOGIN_TTL_SECONDS=900
```

Este modo inicial não suporta WebSockets ou WebAuthn. Use-o apenas em aplicações
próprias e previamente autorizadas.

- Termine TLS antes do Inlock e use `INLOCK_SECURE_COOKIES=true`.
- Configure somente proxies confiáveis em `INLOCK_TRUSTED_PROXIES`; apenas eles
  podem fornecer `CF-Connecting-IP` ou `X-Forwarded-For`. Com `cloudflared` no
  mesmo host, inclua `127.0.0.1/32,::1/128`; em Docker, inclua também apenas a
  rede usada pelo container do tunnel. O Inlock prioriza `CF-Connecting-IP`,
  que o Cloudflare envia com o IP original do visitante.
- O rate limiter desta versão vive em memória. Execute um worker ou substitua o
  backend por Redis antes de escalar horizontalmente.
- Respostas HTTP incrementais (SSE, NDJSON e downloads em streaming) são
  encaminhadas sem buffering e sem timeout de leitura entre chunks. WebSocket
  ainda não é encaminhado nesta versão.
- A tomada transparente pressupõe HTTP. Para uma porta HTTPS, termine TLS em
  Caddy/Nginx antes do Inlock, pois o gateway não possui o certificado privado
  do container.
- Mantenha upstreams não gerenciados inacessíveis pela rede pública. Em projetos
  vinculados a containers, o `INLOCK_GUARD` realiza esse bloqueio automaticamente.

## Estrutura

```text
inlock/
├── main.py              # API, gateway, QR e reverse proxy
├── policies.py          # avaliador de políticas
├── docker_discovery.py  # inspeção read-only do daemon
├── store.py             # persistência SQLite
├── security.py          # tokens, IP real e autenticação admin
├── ui.py                # SSR PyReact/UIKitPR/6cons
└── static/               # painel, gate e Leaflet local
```

Licença MIT.
