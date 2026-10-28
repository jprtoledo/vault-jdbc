# vault-jdbc

[English](README.md)

Driver JDBC que busca usuário e senha do banco no [HashiCorp Vault](https://www.vaultproject.io/) e repassa
a conexão para o driver real (PostgreSQL, MySQL, MariaDB, Aurora…).

- **Um jar só.** O driver real é baixado do Maven Central no primeiro uso e conferido com um SHA-256 fixo
  no código. Também dá para usar o seu próprio jar.
- **Roles dinâmicas e estáticas da engine `database`, e KV v1/v2.**
- **Login no Vault.** Usa o token do `vault login` (`~/.vault-token`). Se ele não existir ou tiver expirado,
  o driver pode rodar o `vault login` por você; no OIDC/Okta, isso abre o navegador.
- **Renovação de credenciais.** A credencial é renovada antes de a lease acabar. Se o banco recusar uma, o
  driver busca outra e tenta de novo.
- **Funciona em qualquer cliente JDBC** que aceite driver customizado: DBX, DBeaver, DataGrip, IntelliJ,
  scripts e aplicações.
- **Requisitos:** Java 17+. Nenhuma dependência em runtime.

## Começando

Compile, ou baixe o jar nas [releases](../../releases):

```bash
mvn package    # target/vault-jdbc-0.1.0.jar
```

Crie uma conexão JDBC genérica no seu cliente:

| Campo | Valor |
|---|---|
| Jar do driver | `vault-jdbc-0.1.0.jar` |
| Classe do driver | `br.com.juantoledo.vaultjdbc.VaultDriver` |
| Usuário / senha | vazios |
| URL | `jdbc:vault:` + a sua URL JDBC de sempre sem o `jdbc:`, mais os parâmetros `vault.*` |

```text
jdbc:vault:postgresql://db.exemplo.com:5432/app?sslmode=require&vault.addr=https://vault.exemplo.com&vault.role=app-read

jdbc:vault:mysql://db.exemplo.com:3306/app?sslMode=REQUIRED&vault.addr=https://vault.exemplo.com&vault.role=app-read&vault.method=oidc&vault.authPath=okta_oidc
```

O segundo exemplo lê `database/creds/app-read`. Se não houver token válido do Vault, ele roda
`vault login -method=oidc -path=okta_oidc` antes.

## Parâmetros

Cada parâmetro `vault.*` pode ir na query da URL ou nas propriedades da conexão; a URL tem prioridade.
Todos são removidos antes de a URL e as propriedades chegarem ao driver real.

### Servidor Vault

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `vault.addr` | `VAULT_ADDR` | Endereço do Vault. Tem que ser `https` (`http` só é aceito para localhost). Apps de interface gráfica normalmente **não** herdam o `VAULT_ADDR` do terminal, então coloque na URL |
| `vault.namespace` | `VAULT_NAMESPACE` | Namespace do Vault Enterprise |
| `vault.cacert` | `VAULT_CACERT` | Arquivo PEM/DER com CAs extras em que confiar para o Vault, além das CAs do JDK |

### Segredo

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `vault.role` | — | Role da engine `database`. Lê `<mount>/creds/<role>` |
| `vault.mount` | `database` | Onde a engine `database` está montada |
| `vault.static` | `false` | Use `true` para role estática. Lê `<mount>/static-creds/<role>` |
| `vault.path` | — | Caminho completo do segredo, no lugar de uma role. Ex.: KV v2 `kv/data/app` ou KV v1 `secret/app` |
| `vault.usernameKey` / `vault.passwordKey` | `username` / `password` | Nomes dos campos dentro do segredo (útil para KV) |
| `vault.cacheSeconds` | `300` | Por quanto tempo guardar um segredo que não tem lease nem TTL (KV) |

Use `vault.role` ou `vault.path`, não os dois.

### Login

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `vault.method` | `token` (padrão do Vault) | Método de autenticação, como no `vault login -method=` (`oidc`, `ldap`, `userpass`, `aws`, `kerberos`, `cert`…). Definir este parâmetro liga o login automático |
| `vault.authPath` | o nome do método | Onde o método está montado, como no `vault login -path=` (ex.: `okta_oidc`) |
| `vault.loginArgs` | — | Argumentos extras `chave=valor` para o `vault login`, separados por vírgula e codificados para URL (ex.: `role%3Ddba`) |
| `vault.autoLogin` | `true` quando há `vault.method` | Se deve rodar o `vault login` quando o token não existe ou é recusado. Nunca roda no método `token`, que precisa de um terminal para pedir o token |
| `vault.loginTimeout` | `120` | Segundos de espera pelo `vault login`, ou seja, o tempo que você tem para concluir o login no navegador |
| `vault.cli` | detectado | Caminho do binário `vault`. É procurado no `PATH` e depois em `/opt/homebrew/bin`, `/usr/local/bin` e `/usr/bin` |
| `vault.tokenFile` | `~/.vault-token` | Arquivo de onde ler o token. Se você não definir, o `VAULT_TOKEN` tem prioridade, como na CLI |

### Driver real

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `vault.driver` | inferido | Classe do driver real. Inferida para `postgresql`, `mysql`, `mariadb` e `aws-wrapper` |
| `vault.driverJar` | — | Caminhos de jars do driver, separados por vírgula, para carregar em vez de baixar |
| `vault.driverDownload` | `true` | Use `false` para nunca baixar drivers |
| `vault.driverVersion` | fixa (ver abaixo) | Baixa outra versão do driver gerenciado |
| `vault.driverSha256` | — | SHA-256 esperado do jar da `vault.driverVersion`. Sem ele, vale o `.sha256` publicado pelo repositório |
| `vault.driverRepo` | `https://repo1.maven.org/maven2` | Repositório Maven de onde baixar, como um mirror interno |
| `vault.driverCacert` | — | Arquivo PEM/DER com CAs extras em que confiar no download, além das CAs do JDK. Necessário atrás de proxy que inspeciona TLS, como o Zscaler |
| `vault.driverCache` | `$XDG_CACHE_HOME/vault-jdbc/drivers` ou `~/.cache/vault-jdbc/drivers` | Onde os drivers baixados ficam guardados |
| `vault.authRetries` | `3` | Quantas vezes tentar de novo quando o banco recusa uma credencial |

Drivers que podem ser baixados automaticamente:

| Subprotocolo | Artefato | Versão |
|---|---|---|
| `postgresql` | `org.postgresql:postgresql` | 42.7.14 |
| `mysql` | `com.mysql:mysql-connector-j` | 26.10.0 |
| `mariadb` | `org.mariadb.jdbc:mariadb-java-client` | 4.0.0 |

O Aurora PostgreSQL e o Aurora MySQL usam os drivers do PostgreSQL e do MySQL.

## Como funciona

**Encontrar o driver real.** A busca segue esta ordem: os jars em `vault.driverJar`; o classpath (por
exemplo, um jar de driver que você configurou ao lado do vault-jdbc); um driver gerenciado no cache,
baixando se for preciso; e, por último, qualquer driver registrado que aceite a URL. Um jar baixado só é
usado se o SHA-256 bater. Se um jar do cache deixar de bater, ele é baixado de novo.

**Token do Vault.** A ordem é: o token do último login automático neste processo, o `VAULT_TOKEN` e o
arquivo de token. Se o Vault responder 401 ou 403, o arquivo é lido de novo, porque você pode ter logado
pelo terminal. Só depois disso o driver roda o `vault login`, se permitido. Só um login acontece por vez
para cada servidor Vault; as outras conexões esperam e reaproveitam o token. A CLI salva o token novo como
de costume, então o seu terminal também passa a usá-lo.

**Credenciais.** Todas as conexões para o mesmo segredo compartilham uma credencial, então um pool de
conexões não cria um usuário de banco por conexão. Uma credencial nova é buscada quando faltam 20% da lease
(no mínimo 30s). Roles estáticas usam o TTL de rotação no lugar da lease.

**Novas tentativas.** Se o banco responder com erro de autenticação (SQLState `28xxx` ou erro `1045` do
MySQL), o driver busca uma credencial nova e tenta de novo. Se a credencial recusada tinha acabado de ser
emitida, ele espera 1s antes, porque o usuário novo pode ainda não existir numa réplica de leitura (por
exemplo, um reader do Aurora).

**Sessões abertas.** Sessões que já estão abertas não são mexidas. Quando o Vault revoga a lease delas, o
banco normalmente as derruba, e a próxima conexão já sai com credencial nova.

**Usernames.** Os espaços em volta do username são removidos, porque algumas configurações de
`username_template` adicionam uma quebra de linha no fim que não faz parte do usuário do banco.

## Segurança

- Senhas e tokens nunca aparecem em log nem em mensagem de erro. Valores sensíveis em `vault.loginArgs`
  (`password`, `secret`, `token`, `passcode`…) são mascarados.
- A verificação de certificado e de hostname do TLS não pode ser desligada. Para confiar numa CA privada
  ou num proxy que inspeciona TLS, adicione a CA com `vault.cacert` ou `vault.driverCacert`.
- Drivers baixados precisam bater com um SHA-256 fixo. Para versões que não estão fixadas, informe o
  `vault.driverSha256`; o checksum do próprio repositório só detecta download corrompido, não um
  repositório malicioso.
- O `vault login` roda sem shell, com argumentos validados e com o stdin fechado, então não fica travado
  esperando um prompt.
- Prefira métodos de login pelo navegador ou por identidade da máquina (`oidc`, `aws`, `kerberos`, `cert`).
  Uma senha em `vault.loginArgs` fica salva junto com a URL da conexão no seu cliente.

## Notas por cliente

**DBX:** use uma conexão *JDBC*. Coloque o timeout de conexão em pelo menos o valor de
`vault.loginTimeout` (ex.: 120s), porque o DBX aplica o próprio timeout e cancelaria a conexão enquanto
você termina o login no navegador. Depois de trocar o jar, reinicie o DBX, porque ele mantém o driver
carregado na memória.

## Desenvolvimento

```bash
mvn verify
```

Os testes usam um Vault falso e um driver falso dentro do próprio processo, então não precisam de Docker
nem de rede.

## Licença

[MIT](LICENSE)
