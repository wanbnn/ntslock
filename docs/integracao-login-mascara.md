# Integrar uma aplicação com o login pela máscara do Inlock

Este guia mostra como uma aplicação protegida pode reconhecer o usuário que se
autenticou pela máscara de login do Inlock. A integração não recebe nem manipula
a senha: depois que o serviço proprietário confirma o login, o Inlock cria um
JWT assinado e o encaminha à aplicação em um cookie.

## Pré-requisitos

No projeto protegido, crie uma política **Login proprietário** e habilite:

1. **Usar tela de login do Inlock**;
2. **Disponibilizar token de autenticação**;
3. os seletores corretos dos campos de login, senha e submit.

Informe também a URL de login e a URL que representa autenticação concluída. O
JWT somente é emitido quando o login veio da máscara e o fluxo alcançou essa URL
de sucesso. O login espelhado sem máscara continua liberando o gateway, mas não
possui um nome de usuário confiável para colocar no token.

Na política é possível configurar:

- **Nome do cookie:** opcional. Sem configuração, será
  `inlock_identity_<slug>`, trocando hífens do slug por sublinhados. Para um
  projeto `meu-sistema`, por exemplo, será `inlock_identity_meu_sistema`.
- **Validade:** 8 horas por padrão, com limite entre 5 minutos e 7 dias.
- **SameSite:** `Lax` por padrão ou `Strict`.

Em produção, configure HTTPS e `INLOCK_SECURE_COOKIES=true`.

## Fluxo de autenticação

1. O visitante abre a aplicação pelo host público cadastrado no Inlock.
2. O Inlock mostra sua máscara e retransmite as credenciais ao login proprietário.
3. Ao reconhecer a URL de sucesso, o Inlock cria o JWT e responde com o cookie.
4. O navegador volta à aplicação protegida.
5. O proxy do Inlock remove seus cookies internos, preserva o cookie JWT de
   integração e, após validá-lo, encaminha ao upstream os headers reservados
   `X-Inlock-Identity-Token`, `X-Inlock-Issuer`, `X-Inlock-Project-ID` e
   `X-Inlock-Project`.
6. O backend da aplicação extrai e valida o JWT antes de criar seu usuário ou
   sua sessão local.

O Inlock remove esses quatro headers de toda requisição recebida antes de inserir
seus próprios valores, impedindo spoofing pelo navegador. O upstream deve ficar
inacessível diretamente, conforme o checklist de produção; os headers constituem
o ponto de confiança zero-config entre o gateway e a aplicação.

O cookie é `HttpOnly`, tem `Path=/` e não define `Domain`. Portanto, JavaScript
executado no navegador não consegue lê-lo, e o navegador o restringe ao host
público pelo qual o usuário acessou o projeto. A validação deve acontecer no
backend da aplicação, nunca no frontend.

## Conteúdo do JWT

O token usa assinatura `EdDSA` com chave Ed25519 e contém:

| Claim | Conteúdo |
| --- | --- |
| `iss` | Valor de `INLOCK_PUBLIC_URL`, sem `/` final |
| `aud` | `inlock:project:<id-do-projeto>` |
| `sub` | Identificador estável e opaco daquele login dentro do projeto |
| `name` | Valor digitado no input de login da máscara |
| `project_id` | ID numérico do projeto no Inlock |
| `project` | Slug do projeto |
| `jti` | Identificador único daquela sessão/token |
| `iat` | Momento de emissão |
| `nbf` | Momento a partir do qual o token é válido |
| `exp` | Momento de expiração |

O header protegido também contém `alg: EdDSA` e o `kid` da chave usada. O `sub`
é apropriado como identificador externo do usuário: o mesmo login normalizado
no mesmo projeto produz o mesmo `sub`, enquanto outro projeto produz um valor
diferente. Não use `name` como chave primária, pois ele é informação de exibição
e pode variar em capitalização ou formato.

Um payload decodificado tem esta aparência:

```json
{
  "iss": "https://inlock.exemplo.com",
  "aud": "inlock:project:7",
  "sub": "F7o3...identificador-opaco...",
  "name": "maria.silva",
  "project_id": 7,
  "project": "meu-sistema",
  "jti": "sessao-unica",
  "iat": 1786550400,
  "nbf": 1786550400,
  "exp": 1786579200
}
```

JWT é assinado, não criptografado. Não coloque o token ou seu payload em logs e
não trate suas claims como válidas antes de verificar a assinatura.

## Validação obrigatória

As chaves públicas são publicadas em:

```text
https://inlock.exemplo.com/.well-known/jwks.json
```

Para cada requisição autenticada, o backend deve:

1. extrair token, issuer, ID e slug dos headers reservados enviados pelo Inlock;
2. selecionar no JWKS a chave cujo `kid` corresponda ao header do JWT;
3. aceitar exclusivamente o algoritmo `EdDSA`;
4. validar assinatura, `exp`, `nbf`, `iss` e `aud`;
5. confirmar que `project_id` e `project` são os esperados;
6. usar `sub` para localizar ou provisionar a conta integrada.

Não aceite o algoritmo informado pelo token sem uma allowlist fixa. Também não
desabilite validação de expiração em produção. Bibliotecas de JWT normalmente
mantêm cache do JWKS e atualizam a chave quando encontram um `kid` novo.

## Exemplo em Python com PyJWT

Instale o suporte criptográfico:

```bash
pip install "PyJWT[crypto]>=2.10,<3"
```

```python
import jwt
from jwt import PyJWKClient

jwks_clients = {}


def authenticated_user(request):
    token = request.headers.get("X-Inlock-Identity-Token")
    issuer = request.headers.get("X-Inlock-Issuer", "").rstrip("/")
    project = request.headers.get("X-Inlock-Project")
    try:
        project_id = int(request.headers.get("X-Inlock-Project-ID", ""))
    except ValueError:
        return None
    if not token or not issuer or not project or project_id <= 0:
        return None

    try:
        jwks = jwks_clients.setdefault(
            issuer, PyJWKClient(f"{issuer}/.well-known/jwks.json")
        )
        signing_key = jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["EdDSA"],
            issuer=issuer,
            audience=f"inlock:project:{project_id}",
            options={
                "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]
            },
        )
    except jwt.PyJWTError:
        return None

    if claims.get("project_id") != project_id or claims.get("project") != project:
        return None
    return {"external_id": claims["sub"], "name": claims["name"]}
```

O objeto `request` varia conforme o framework, mas ele deve representar a
requisição que chegou ao backend protegido pelo Inlock.

## Exemplo em Node.js com `jose`

```bash
npm install jose
```

```javascript
import { createRemoteJWKSet, jwtVerify } from 'jose'

const jwksByIssuer = new Map()

export async function authenticatedUser(request) {
  const token = request.headers['x-inlock-identity-token']
  const issuer = request.headers['x-inlock-issuer']?.replace(/\/$/, '')
  const project = request.headers['x-inlock-project']
  const projectId = Number(request.headers['x-inlock-project-id'])
  if (!token || !issuer || !project || !Number.isSafeInteger(projectId)) return null

  try {
    let JWKS = jwksByIssuer.get(issuer)
    if (!JWKS) {
      JWKS = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`))
      jwksByIssuer.set(issuer, JWKS)
    }
    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ['EdDSA'],
      issuer,
      audience: `inlock:project:${projectId}`,
      requiredClaims: ['exp', 'iat', 'nbf', 'iss', 'aud', 'sub', 'jti'],
    })

    if (payload.project_id !== projectId || payload.project !== project) return null
    return { externalId: payload.sub, name: payload.name }
  } catch {
    return null
  }
}
```

A forma de acessar headers depende do framework. Em Express, Fastify, Next.js ou
outro servidor, adapte somente essa leitura; mantenha as verificações do JWT. Não
aceite esses headers por uma porta pública que contorne o Inlock.

## Revogação imediata

Validar apenas a assinatura permite operação local e rápida. Nesse modo, um JWT
já emitido continua válido até `exp`, mesmo que sua sessão seja revogada no
Inlock. Para operações sensíveis ou quando a aplicação exige revogação imediata,
consulte:

```http
POST /api/identity/introspect
Content-Type: application/json

{"token":"<JWT recebido no cookie>"}
```

Resposta ativa:

```json
{
  "active": true,
  "sub": "F7o3...",
  "name": "maria.silva",
  "project_id": 7,
  "jti": "sessao-unica"
}
```

Tokens inválidos, expirados, associados a uma chave revogada ou com sessão
revogada retornam `{"active": false}`. A aplicação pode validar localmente em
todas as requisições e reservar a introspecção para ações críticas, ou manter um
cache curto do resultado conforme seu risco aceitável.

## Rotação de chaves

O Inlock persiste as chaves em `data/signing-keys`. Atualizações ou reinstalações
que preservem o diretório de dados mantêm as mesmas chaves. Ao rotacionar, novos
tokens passam a usar um novo `kid`, enquanto a chave pública anterior continua
no JWKS pelo período máximo de validade dos tokens.

Por isso, a aplicação não deve fixar uma única chave pública em seu código. Use
o endpoint JWKS e permita que a biblioteca atualize o cache quando aparecer um
novo `kid`.

## Checklist de produção

- A aplicação só é acessível através do Inlock, sem bypass pela porta do upstream.
- `INLOCK_PUBLIC_URL` contém o emissor público definitivo.
- `INLOCK_SECURE_COOKIES=true` e todo o tráfego usa HTTPS.
- O backend aceita somente `EdDSA` e valida issuer, audience e tempo.
- O backend compara o ID e o slug assinados no JWT com os headers atestados pelo gateway.
- `sub`, e não `name`, é usado para vincular a conta local.
- Tokens, cookies e payloads JWT não são escritos em logs.
- A estratégia de introspecção está definida conforme a necessidade de revogação.
- O diretório de dados do Inlock faz parte do backup seguro.

## Diagnóstico rápido

**O cookie não chega à aplicação:** confirme que a política usa a máscara, que
**Disponibilizar token de autenticação** está habilitado e que o login alcançou a
URL de sucesso. Confira também se a aplicação está sendo acessada pelo host
público protegido, e não diretamente pelo upstream.

**O cookie aparece no navegador, mas não no JavaScript:** é o comportamento
esperado de `HttpOnly`. Leia-o no backend.

**Issuer inválido:** o valor esperado precisa ser exatamente
`INLOCK_PUBLIC_URL`, removendo apenas a barra final.

**Audience inválida:** use `inlock:project:<id>`, com o ID numérico do projeto,
e não seu slug.

**Falha após rotação:** não mantenha uma chave Ed25519 fixa. Atualize a chave pelo
JWKS de acordo com o `kid` do token.
